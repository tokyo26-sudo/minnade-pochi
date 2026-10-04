-- ============================================================
--  みんなでポチッ（アンケート機能）  Supabase セットアップ用SQL
--  Supabase の「SQL Editor」に全部貼りつけて「Run」するだけ。
--  いちばん下の「マスターパスワード」だけ、自分のものに書きかえてね。
-- ============================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------- テーブル ----------
create table if not exists public.ev_config (
  id          int  primary key default 1 check (id = 1),
  master_hash text not null
);

create table if not exists public.ev_rooms (
  code       text primary key,
  pin        text not null,
  secret     text not null,
  title      text not null default '',
  anon_mode  text not null check (anon_mode in ('full','master','named')),
  state      jsonb not null default '{"phase":"waiting","rev":1}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.ev_participants (
  room_code text not null references public.ev_rooms(code) on delete cascade,
  device_id text not null,
  name      text not null,
  joined_at timestamptz not null default now(),
  primary key (room_code, device_id)
);

create table if not exists public.ev_runs (
  room_code  text not null references public.ev_rooms(code) on delete cascade,
  run_id     text not null,
  question   text not null,
  options    jsonb not null,
  settings   jsonb not null default '{}'::jsonb,
  started_at timestamptz not null default now(),
  primary key (room_code, run_id)
);

-- 完全匿名モードでは voter_key は「投票用のでたらめな記号」で、名前とはつながらない
create table if not exists public.ev_votes (
  room_code  text not null,
  run_id     text not null,
  voter_key  text not null,
  choice     int  not null,
  updated_at timestamptz not null default now(),
  primary key (room_code, run_id, voter_key),
  foreign key (room_code, run_id) references public.ev_runs(room_code, run_id) on delete cascade
);
alter table public.ev_runs add column if not exists settings jsonb not null default '{}'::jsonb;
create index if not exists ev_votes_tally on public.ev_votes (room_code, run_id, choice);

-- テーブルは直接さわれないようにする（ぜんぶ下の関数経由）
alter table public.ev_config       enable row level security;
alter table public.ev_rooms        enable row level security;
alter table public.ev_participants enable row level security;
alter table public.ev_runs         enable row level security;
alter table public.ev_votes        enable row level security;
revoke all on public.ev_config, public.ev_rooms, public.ev_participants, public.ev_runs, public.ev_votes from anon, authenticated;

-- ---------- 内部用の関数 ----------
create or replace function public.ev_now_ms() returns bigint
language sql volatile as $$ select (extract(epoch from clock_timestamp()) * 1000)::bigint $$;

create or replace function public.ev_rand_code(n int) returns text
language plpgsql volatile set search_path = public, extensions as $$
declare
  chars text := 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  b bytea := gen_random_bytes(n);
  r text := '';
begin
  for i in 0..n-1 loop
    r := r || substr(chars, (get_byte(b, i) % length(chars)) + 1, 1);
  end loop;
  return r;
end $$;

-- 24時間たった部屋は、参加者・結果ごと消える
create or replace function public.ev_cleanup() returns void
language sql security definer set search_path = public as $$
  delete from public.ev_rooms where created_at < now() - interval '24 hours';
$$;

create or replace function public.ev_tally(p_code text, p_run text, p_names boolean) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare v_n int; v_counts jsonb; v_names jsonb; v_total int;
begin
  select jsonb_array_length(options) into v_n from ev_runs where room_code = p_code and run_id = p_run;
  if v_n is null then return null; end if;

  select coalesce(jsonb_agg(t.c order by t.i), '[]'::jsonb) into v_counts from (
    select g.i, (select count(*) from ev_votes v
                  where v.room_code = p_code and v.run_id = p_run and v.choice = g.i) as c
    from generate_series(0, v_n - 1) as g(i)) t;

  select count(*) into v_total from ev_votes where room_code = p_code and run_id = p_run;

  if p_names then
    select coalesce(jsonb_agg(t.nm order by t.i), '[]'::jsonb) into v_names from (
      select g.i, coalesce((select jsonb_agg(p.name order by v.updated_at)
                              from ev_votes v
                              join ev_participants p on p.room_code = v.room_code and p.device_id = v.voter_key
                             where v.room_code = p_code and v.run_id = p_run and v.choice = g.i), '[]'::jsonb) as nm
      from generate_series(0, v_n - 1) as g(i)) t;
  end if;

  return jsonb_build_object('counts', v_counts, 'total', v_total, 'names', v_names);
end $$;

-- ---------- アプリから呼ぶ関数 ----------
create or replace function public.ev_create_room(p_password text, p_title text, p_anon text) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
declare v_hash text; v_code text; v_pin text; v_secret text;
begin
  perform ev_cleanup();
  select master_hash into v_hash from ev_config where id = 1;
  if v_hash is null then
    return jsonb_build_object('ok', false, 'error', 'no_password_set', 'server_now', ev_now_ms());
  end if;
  if p_password is null or crypt(p_password, v_hash) <> v_hash then
    return jsonb_build_object('ok', false, 'error', 'bad_password', 'server_now', ev_now_ms());
  end if;
  if p_anon is null or p_anon not in ('full','master','named') then
    return jsonb_build_object('ok', false, 'error', 'bad_mode', 'server_now', ev_now_ms());
  end if;
  loop
    v_code := ev_rand_code(6);
    exit when not exists (select 1 from ev_rooms where code = v_code);
  end loop;
  v_pin := lpad(((get_byte(gen_random_bytes(1), 0) * 256 + get_byte(gen_random_bytes(1), 0)) % 10000)::text, 4, '0');
  v_secret := encode(gen_random_bytes(24), 'hex');
  insert into ev_rooms (code, pin, secret, title, anon_mode)
  values (v_code, v_pin, v_secret, left(coalesce(p_title, ''), 60), p_anon);
  return jsonb_build_object('ok', true, 'code', v_code, 'pin', v_pin, 'secret', v_secret, 'server_now', ev_now_ms());
end $$;

create or replace function public.ev_op_state(p_code text, p_secret text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare r ev_rooms;
begin
  select * into r from ev_rooms
   where code = upper(p_code) and secret = p_secret and created_at > now() - interval '24 hours';
  if not found then return jsonb_build_object('ok', false, 'error', 'no_room', 'server_now', ev_now_ms()); end if;
  return jsonb_build_object(
    'ok', true,
    'room', jsonb_build_object('code', r.code, 'pin', r.pin, 'title', r.title, 'anon_mode', r.anon_mode,
                               'state', r.state, 'created_at', (extract(epoch from r.created_at) * 1000)::bigint),
    'participants', (select count(*) from ev_participants where room_code = r.code),
    'server_now', ev_now_ms());
end $$;

create or replace function public.ev_set_state(p_code text, p_secret text, p_state jsonb, p_duration int, p_run jsonb) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare r ev_rooms; v_state jsonb; v_len int;
begin
  select * into r from ev_rooms
   where code = upper(p_code) and secret = p_secret and created_at > now() - interval '24 hours'
   for update;
  if not found then return jsonb_build_object('ok', false, 'error', 'no_room', 'server_now', ev_now_ms()); end if;

  v_state := coalesce(p_state, '{"phase":"waiting"}'::jsonb);
  if p_run is not null then
    if jsonb_typeof(p_run->'options') is distinct from 'array' then
      return jsonb_build_object('ok', false, 'error', 'bad_run', 'server_now', ev_now_ms());
    end if;
    v_len := jsonb_array_length(p_run->'options');
    if v_len < 2 or v_len > 6 or coalesce(p_run->>'id', '') = '' then
      return jsonb_build_object('ok', false, 'error', 'bad_run', 'server_now', ev_now_ms());
    end if;
    insert into ev_runs (room_code, run_id, question, options, settings)
    values (r.code, p_run->>'id', left(coalesce(p_run->>'question', ''), 300), p_run->'options',
            case when jsonb_typeof(p_run->'settings') = 'object' then p_run->'settings' else '{}'::jsonb end)
    on conflict (room_code, run_id) do nothing;
  end if;
  -- 締め切り時刻はサーバーの時計で決める
  if coalesce(p_duration, 0) > 0 then
    v_state := v_state || jsonb_build_object('ends_at', ev_now_ms() + p_duration::bigint * 1000);
  end if;
  v_state := v_state || jsonb_build_object('rev', coalesce((r.state->>'rev')::int, 0) + 1);
  update ev_rooms set state = v_state where code = r.code;
  return jsonb_build_object('ok', true, 'state', v_state, 'server_now', ev_now_ms());
end $$;

create or replace function public.ev_regen_pin(p_code text, p_secret text) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
declare r ev_rooms; v_pin text;
begin
  select * into r from ev_rooms
   where code = upper(p_code) and secret = p_secret and created_at > now() - interval '24 hours';
  if not found then return jsonb_build_object('ok', false, 'error', 'no_room', 'server_now', ev_now_ms()); end if;
  loop
    v_pin := lpad(((get_byte(gen_random_bytes(1), 0) * 256 + get_byte(gen_random_bytes(1), 0)) % 10000)::text, 4, '0');
    exit when v_pin <> r.pin;
  end loop;
  update ev_rooms set pin = v_pin where code = r.code;
  return jsonb_build_object('ok', true, 'pin', v_pin, 'server_now', ev_now_ms());
end $$;

create or replace function public.ev_public_state(p_code text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare r ev_rooms;
begin
  select * into r from ev_rooms where code = upper(p_code) and created_at > now() - interval '24 hours';
  if not found then return jsonb_build_object('ok', false, 'error', 'no_room', 'server_now', ev_now_ms()); end if;
  return jsonb_build_object('ok', true, 'title', r.title, 'anon_mode', r.anon_mode, 'state', r.state, 'server_now', ev_now_ms());
end $$;

create or replace function public.ev_join(p_code text, p_pin text, p_device text, p_name text) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare r ev_rooms; v_name text := btrim(coalesce(p_name, ''));
begin
  if char_length(v_name) < 1 or char_length(v_name) > 20 then
    return jsonb_build_object('ok', false, 'error', 'bad_name', 'server_now', ev_now_ms());
  end if;
  if p_device is null or char_length(p_device) < 8 or char_length(p_device) > 64 then
    return jsonb_build_object('ok', false, 'error', 'bad_device', 'server_now', ev_now_ms());
  end if;
  select * into r from ev_rooms where code = upper(p_code) and created_at > now() - interval '24 hours';
  if not found then return jsonb_build_object('ok', false, 'error', 'no_room', 'server_now', ev_now_ms()); end if;
  if r.pin is distinct from p_pin then
    return jsonb_build_object('ok', false, 'error', 'bad_pin', 'server_now', ev_now_ms());
  end if;
  if (select count(*) from ev_participants where room_code = r.code) >= 500
     and not exists (select 1 from ev_participants where room_code = r.code and device_id = p_device) then
    return jsonb_build_object('ok', false, 'error', 'room_full', 'server_now', ev_now_ms());
  end if;
  insert into ev_participants (room_code, device_id, name) values (r.code, p_device, v_name)
  on conflict (room_code, device_id) do update set name = excluded.name;
  return jsonb_build_object('ok', true, 'server_now', ev_now_ms());
end $$;

create or replace function public.ev_vote(p_code text, p_device text, p_voter_key text, p_run_id text, p_choice int) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare r ev_rooms; v_n int; v_key text;
begin
  select * into r from ev_rooms where code = upper(p_code) and created_at > now() - interval '24 hours';
  if not found then return jsonb_build_object('ok', false, 'error', 'no_room', 'server_now', ev_now_ms()); end if;
  if not exists (select 1 from ev_participants where room_code = r.code and device_id = p_device) then
    return jsonb_build_object('ok', false, 'error', 'not_joined', 'server_now', ev_now_ms());
  end if;
  if (r.state->>'phase') is distinct from 'open' or (r.state->'run'->>'id') is distinct from p_run_id then
    return jsonb_build_object('ok', false, 'error', 'closed', 'server_now', ev_now_ms());
  end if;
  -- サーバーの時計で締め切りチェック（通信の遅れぶん1.5秒だけ猶予）
  if (r.state ? 'ends_at') and ev_now_ms() > (r.state->>'ends_at')::bigint + 1500 then
    return jsonb_build_object('ok', false, 'error', 'closed', 'server_now', ev_now_ms());
  end if;
  v_n := jsonb_array_length(r.state->'run'->'options');
  if p_choice is null or p_choice < 0 or p_choice >= v_n then
    return jsonb_build_object('ok', false, 'error', 'bad_choice', 'server_now', ev_now_ms());
  end if;
  if r.anon_mode = 'full' then
    -- 完全匿名：名前とつながる device_id は保存しない
    v_key := p_voter_key;
    if v_key is null or char_length(v_key) < 8 or char_length(v_key) > 64 or v_key = p_device then
      return jsonb_build_object('ok', false, 'error', 'bad_key', 'server_now', ev_now_ms());
    end if;
  else
    v_key := p_device;
  end if;
  insert into ev_votes (room_code, run_id, voter_key, choice, updated_at)
  values (r.code, p_run_id, v_key, p_choice, now())
  on conflict (room_code, run_id, voter_key) do update set choice = excluded.choice, updated_at = now();
  return jsonb_build_object('ok', true, 'server_now', ev_now_ms());
end $$;

create or replace function public.ev_results(p_code text, p_secret text, p_run_id text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare r ev_rooms; t jsonb;
begin
  select * into r from ev_rooms
   where code = upper(p_code) and secret = p_secret and created_at > now() - interval '24 hours';
  if not found then return jsonb_build_object('ok', false, 'error', 'no_room', 'server_now', ev_now_ms()); end if;
  t := ev_tally(r.code, p_run_id, r.anon_mode <> 'full');
  if t is null then return jsonb_build_object('ok', false, 'error', 'no_run', 'server_now', ev_now_ms()); end if;
  return jsonb_build_object('ok', true, 'server_now', ev_now_ms(),
           'participants', (select count(*) from ev_participants where room_code = r.code)) || t;
end $$;

create or replace function public.ev_export(p_code text, p_secret text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare r ev_rooms;
begin
  select * into r from ev_rooms
   where code = upper(p_code) and secret = p_secret and created_at > now() - interval '24 hours';
  if not found then return jsonb_build_object('ok', false, 'error', 'no_room', 'server_now', ev_now_ms()); end if;
  return jsonb_build_object('ok', true, 'server_now', ev_now_ms(), 'title', r.title, 'anon_mode', r.anon_mode,
    'runs', coalesce((
      select jsonb_agg(jsonb_build_object('run_id', x.run_id, 'question', x.question, 'options', x.options, 'settings', x.settings,
                                          'started_at', (extract(epoch from x.started_at) * 1000)::bigint)
                       || coalesce(ev_tally(r.code, x.run_id, r.anon_mode <> 'full'), '{}'::jsonb)
                       order by x.started_at)
        from ev_runs x where x.room_code = r.code), '[]'::jsonb));
end $$;

create or replace function public.ev_close_room(p_code text, p_secret text) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
begin
  delete from ev_rooms where code = upper(p_code) and secret = p_secret;
  return jsonb_build_object('ok', true, 'server_now', ev_now_ms());
end $$;

-- ---------- 実行権限 ----------
revoke execute on function public.ev_cleanup()                   from public, anon, authenticated;
revoke execute on function public.ev_tally(text, text, boolean)  from public, anon, authenticated;
revoke execute on function public.ev_rand_code(int)              from public, anon, authenticated;

grant execute on function public.ev_now_ms()                                      to anon, authenticated;
grant execute on function public.ev_create_room(text, text, text)                 to anon, authenticated;
grant execute on function public.ev_op_state(text, text)                          to anon, authenticated;
grant execute on function public.ev_set_state(text, text, jsonb, int, jsonb)      to anon, authenticated;
grant execute on function public.ev_regen_pin(text, text)                         to anon, authenticated;
grant execute on function public.ev_public_state(text)                            to anon, authenticated;
grant execute on function public.ev_join(text, text, text, text)                  to anon, authenticated;
grant execute on function public.ev_vote(text, text, text, text, int)             to anon, authenticated;
grant execute on function public.ev_results(text, text, text)                     to anon, authenticated;
grant execute on function public.ev_export(text, text)                            to anon, authenticated;
grant execute on function public.ev_close_room(text, text)                        to anon, authenticated;

-- ============================================================
--  ★ マスターパスワード（部屋をつくるときに使う）
--     'ここをパスワードに' を好きな文字に書きかえてから Run。
--     あとで変えたいときも、この1文だけ実行すればOK。
-- ============================================================
insert into public.ev_config (id, master_hash)
values (1, extensions.crypt('ここをパスワードに', extensions.gen_salt('bf')))
on conflict (id) do update set master_hash = excluded.master_hash;

-- （おまけ）pg_cron が使えるなら、1時間ごとに古い部屋をおそうじ：
-- select cron.schedule('ev-cleanup', '0 * * * *', 'select public.ev_cleanup()');
