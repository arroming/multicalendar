-- =========================================================
-- 멀티 캘린더 · Supabase 스키마 (v2: 이름 + 숫자 4자리 로그인)
-- Supabase 대시보드 → SQL Editor → New query 에 전체를 붙여 넣고 Run.
-- 여러 번 실행해도 안전합니다. (v1을 이미 실행했어도 그대로 실행하면 정리됩니다)
--
-- 로그인 방식
--   · 기기마다 Supabase "익명 로그인" 세션을 하나 만들고,
--   · 이름 + 숫자 4자리를 확인하면 그 기기를 가족 구성원(profile)과 연결합니다.
--   · 숫자 4자리는 암호화(bcrypt)해서 저장하고, 5번 틀리면 10분 동안 잠깁니다.
--   · 가족 자리(max_members, 기본 3명)가 다 차면 더 이상 등록할 수 없습니다.
--
-- 테이블
--   spaces       : 가족 캘린더 (한 집에 하나)
--   profiles     : 가족 구성원 (이름, 숫자 4자리 암호)
--   device_links : 어느 기기(세션)가 누구로 로그인했는지
--   records      : 캘린더 기록 한 건 = 한 줄
--                  key 예) cat:<탭id>, event:<일정id>,
--                          habit:<탭id>:<날짜>, note:<탭id>:<날짜>
-- =========================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------- v1 정리 (이메일 방식, 저장된 데이터 없음) ----------
drop function if exists public.ensure_space();
drop table if exists public.space_members cascade;

-- ---------- 테이블 ----------
create table if not exists public.spaces (
  id          uuid primary key default gen_random_uuid(),
  name        text not null default '우리 가족',
  max_members int  not null default 3,
  created_at  timestamptz not null default now()
);
alter table public.spaces drop column if exists created_by;
alter table public.spaces add column if not exists max_members int not null default 3;
alter table public.spaces alter column name set default '우리 가족';

create table if not exists public.profiles (
  id           uuid primary key default gen_random_uuid(),
  space_id     uuid not null references public.spaces(id) on delete cascade,
  name         text not null check (char_length(name) between 1 and 10),
  pin_hash     text not null,
  failed_count int  not null default 0,
  locked_until timestamptz,
  created_at   timestamptz not null default now()
);
create unique index if not exists profiles_space_name_idx on public.profiles (space_id, lower(name));

create table if not exists public.device_links (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  profile_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.records (
  space_id    uuid not null references public.spaces(id) on delete cascade,
  key         text not null,
  data        jsonb,
  deleted     boolean not null default false,
  updated_at  timestamptz not null default now(),
  updated_by  uuid,
  primary key (space_id, key)
);
alter table public.records drop constraint if exists records_updated_by_fkey;
create index if not exists records_space_updated_idx on public.records (space_id, updated_at);

-- 수정 시각·수정한 기기 자동 기록
create or replace function public.touch_record() returns trigger
language plpgsql set search_path = public as $$
begin
  new.updated_at := now();
  new.updated_by := auth.uid();
  return new;
end $$;

drop trigger if exists records_touch on public.records;
create trigger records_touch before insert or update on public.records
  for each row execute function public.touch_record();

-- ---------- 함수 ----------
-- 지금 기기가 이 가족 캘린더에 로그인돼 있는지 (접근 권한 규칙에서 사용)
create or replace function public.is_member(sid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.device_links d
    join public.profiles p on p.id = d.profile_id
    where d.user_id = auth.uid() and p.space_id = sid
  );
$$;

-- 기기를 구성원과 연결
create or replace function public.link_device(pid uuid) returns void
language sql security definer set search_path = public as $$
  insert into public.device_links (user_id, profile_id) values (auth.uid(), pid)
  on conflict (user_id) do update set profile_id = excluded.profile_id, created_at = now();
$$;

-- 가족 등록: 이름 + 숫자 4자리
create or replace function public.register(p_name text, p_pin text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_name text := btrim(coalesce(p_name, ''));
  sid uuid; maxm int; cnt int; pid uuid;
begin
  if auth.uid() is null then return jsonb_build_object('error', 'no_session'); end if;
  if char_length(v_name) < 1 or char_length(v_name) > 10 then return jsonb_build_object('error', 'bad_name'); end if;
  if coalesce(p_pin, '') !~ '^[0-9]{4}$' then return jsonb_build_object('error', 'bad_pin'); end if;

  select id, max_members into sid, maxm from public.spaces order by created_at limit 1 for update;
  if sid is null then
    insert into public.spaces default values returning id, max_members into sid, maxm;
  end if;
  if exists (select 1 from public.profiles where space_id = sid and lower(name) = lower(v_name)) then
    return jsonb_build_object('error', 'name_taken');
  end if;
  select count(*) into cnt from public.profiles where space_id = sid;
  if cnt >= maxm then return jsonb_build_object('error', 'family_full'); end if;

  insert into public.profiles (space_id, name, pin_hash)
    values (sid, v_name, extensions.crypt(p_pin, extensions.gen_salt('bf')))
    returning id into pid;
  perform public.link_device(pid);
  return jsonb_build_object('profile_id', pid, 'name', v_name, 'space_id', sid);
end $$;

-- 로그인: 이름 + 숫자 4자리 (5번 틀리면 10분 잠금)
create or replace function public.login(p_name text, p_pin text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare pr public.profiles%rowtype;
begin
  if auth.uid() is null then return jsonb_build_object('error', 'no_session'); end if;
  select * into pr from public.profiles
    where lower(name) = lower(btrim(coalesce(p_name, '')))
    order by created_at limit 1 for update;
  if not found then return jsonb_build_object('error', 'not_found'); end if;
  if pr.locked_until is not null and pr.locked_until > now() then
    return jsonb_build_object('error', 'locked', 'until', pr.locked_until);
  end if;
  if extensions.crypt(coalesce(p_pin, ''), pr.pin_hash) <> pr.pin_hash then
    update public.profiles set
      failed_count = case when pr.failed_count + 1 >= 5 then 0 else pr.failed_count + 1 end,
      locked_until = case when pr.failed_count + 1 >= 5 then now() + interval '10 minutes' else null end
      where id = pr.id;
    if pr.failed_count + 1 >= 5 then return jsonb_build_object('error', 'locked'); end if;
    return jsonb_build_object('error', 'wrong_pin', 'left', 4 - pr.failed_count);
  end if;
  update public.profiles set failed_count = 0, locked_until = null where id = pr.id;
  perform public.link_device(pr.id);
  return jsonb_build_object('profile_id', pr.id, 'name', pr.name, 'space_id', pr.space_id);
end $$;

-- 지금 기기에 로그인한 사람
create or replace function public.whoami() returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object('profile_id', p.id, 'name', p.name, 'space_id', p.space_id)
  from public.device_links d join public.profiles p on p.id = d.profile_id
  where d.user_id = auth.uid();
$$;

-- 로그아웃 (이 기기 연결 해제)
create or replace function public.logout() returns void
language sql security definer set search_path = public as $$
  delete from public.device_links where user_id = auth.uid();
$$;

-- 가족 구성원 이름 목록 (로그인한 사람만)
create or replace function public.family_members() returns table (id uuid, name text)
language sql stable security definer set search_path = public as $$
  select p.id, p.name from public.profiles p
  where public.is_member(p.space_id)
  order by p.created_at;
$$;

revoke execute on function public.is_member(uuid)       from public, anon;
revoke execute on function public.link_device(uuid)     from public, anon, authenticated;
revoke execute on function public.register(text, text)  from public, anon;
revoke execute on function public.login(text, text)     from public, anon;
revoke execute on function public.whoami()              from public, anon;
revoke execute on function public.logout()              from public, anon;
revoke execute on function public.family_members()      from public, anon;
grant  execute on function public.is_member(uuid)       to authenticated;
grant  execute on function public.register(text, text)  to authenticated;
grant  execute on function public.login(text, text)     to authenticated;
grant  execute on function public.whoami()              to authenticated;
grant  execute on function public.logout()              to authenticated;
grant  execute on function public.family_members()      to authenticated;

-- ---------- 접근 권한 (Row Level Security) ----------
alter table public.spaces       enable row level security;
alter table public.profiles     enable row level security;
alter table public.device_links enable row level security;
alter table public.records      enable row level security;

-- profiles, device_links: 직접 읽기·쓰기 금지 (위 함수로만 접근 → 숫자 암호가 밖으로 나가지 않음)
revoke all on public.profiles     from anon, authenticated;
revoke all on public.device_links from anon, authenticated;

drop policy if exists "members read space"   on public.spaces;
drop policy if exists "members rename space" on public.spaces;
create policy "members read space" on public.spaces
  for select to authenticated using (public.is_member(id));
create policy "members rename space" on public.spaces
  for update to authenticated using (public.is_member(id)) with check (public.is_member(id));

drop policy if exists "members read records"   on public.records;
drop policy if exists "members add records"    on public.records;
drop policy if exists "members edit records"   on public.records;
drop policy if exists "members delete records" on public.records;
create policy "members read records" on public.records
  for select to authenticated using (public.is_member(space_id));
create policy "members add records" on public.records
  for insert to authenticated with check (public.is_member(space_id));
create policy "members edit records" on public.records
  for update to authenticated using (public.is_member(space_id)) with check (public.is_member(space_id));
create policy "members delete records" on public.records
  for delete to authenticated using (public.is_member(space_id));

revoke all on public.spaces  from anon;
revoke all on public.records from anon;
grant select, update                 on public.spaces  to authenticated;
grant select, insert, update, delete on public.records to authenticated;

-- 다른 기기에 바로 반영되도록 실시간 알림 켜기
do $$
begin
  alter publication supabase_realtime add table public.records;
exception when duplicate_object then null;
end $$;
