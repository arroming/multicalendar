-- =========================================================
-- 멀티 캘린더 · Supabase 스키마
-- Supabase 대시보드 → SQL Editor → New query 에 전체를 붙여 넣고 Run.
-- 여러 번 실행해도 안전하도록 작성했습니다.
--
-- 구조
--   spaces        : 캘린더 공간 (개인 또는 가족 공용)
--   space_members : 공간에 속한 사람 (owner / member)
--   records       : 공간 안의 기록 한 건 = 한 줄
--                   key 예) cat:<탭id>, event:<일정id>,
--                           habit:<탭id>:<날짜>, note:<탭id>:<날짜>
--   → 가족이 서로 다른 날짜·일정을 고쳐도 서로 덮어쓰지 않습니다.
-- =========================================================

create table if not exists public.spaces (
  id          uuid primary key default gen_random_uuid(),
  name        text not null default '내 캘린더',
  created_by  uuid not null references auth.users(id) on delete cascade,
  created_at  timestamptz not null default now()
);

create table if not exists public.space_members (
  space_id    uuid not null references public.spaces(id) on delete cascade,
  user_id     uuid not null references auth.users(id) on delete cascade,
  role        text not null default 'member' check (role in ('owner', 'member')),
  created_at  timestamptz not null default now(),
  primary key (space_id, user_id)
);

create table if not exists public.records (
  space_id    uuid not null references public.spaces(id) on delete cascade,
  key         text not null,
  data        jsonb,
  deleted     boolean not null default false,
  updated_at  timestamptz not null default now(),
  updated_by  uuid references auth.users(id) on delete set null,
  primary key (space_id, key)
);
create index if not exists records_space_updated_idx on public.records (space_id, updated_at);

-- 수정 시각·수정한 사람 자동 기록
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

-- 로그인한 사람이 해당 공간의 멤버인지 (RLS 안에서 재귀 없이 쓰기 위해 security definer)
create or replace function public.is_member(sid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.space_members
    where space_id = sid and user_id = auth.uid()
  );
$$;

-- 처음 로그인하면 개인 공간을 만들고, 이미 있으면 그 공간 id를 돌려줌
create or replace function public.ensure_space() returns uuid
language plpgsql security definer set search_path = public as $$
declare sid uuid;
begin
  if auth.uid() is null then
    raise exception 'not signed in';
  end if;
  select space_id into sid from public.space_members
    where user_id = auth.uid() order by created_at limit 1;
  if sid is null then
    insert into public.spaces (name, created_by) values ('내 캘린더', auth.uid()) returning id into sid;
    insert into public.space_members (space_id, user_id, role) values (sid, auth.uid(), 'owner');
  end if;
  return sid;
end $$;

revoke execute on function public.is_member(uuid) from public, anon;
revoke execute on function public.ensure_space() from public, anon;
grant execute on function public.is_member(uuid) to authenticated;
grant execute on function public.ensure_space() to authenticated;

-- ---------- 접근 권한 (Row Level Security) ----------
-- 로그인한 본인이 속한 공간의 데이터만 보고 쓸 수 있음
alter table public.spaces        enable row level security;
alter table public.space_members enable row level security;
alter table public.records       enable row level security;

drop policy if exists "members read space" on public.spaces;
create policy "members read space" on public.spaces
  for select to authenticated using (public.is_member(id));

drop policy if exists "members rename space" on public.spaces;
create policy "members rename space" on public.spaces
  for update to authenticated using (public.is_member(id)) with check (public.is_member(id));

drop policy if exists "members see members" on public.space_members;
create policy "members see members" on public.space_members
  for select to authenticated using (public.is_member(space_id));

drop policy if exists "leave space" on public.space_members;
create policy "leave space" on public.space_members
  for delete to authenticated using (user_id = auth.uid());

drop policy if exists "members read records" on public.records;
create policy "members read records" on public.records
  for select to authenticated using (public.is_member(space_id));

drop policy if exists "members add records" on public.records;
create policy "members add records" on public.records
  for insert to authenticated with check (public.is_member(space_id));

drop policy if exists "members edit records" on public.records;
create policy "members edit records" on public.records
  for update to authenticated using (public.is_member(space_id)) with check (public.is_member(space_id));

drop policy if exists "members delete records" on public.records;
create policy "members delete records" on public.records
  for delete to authenticated using (public.is_member(space_id));

grant select, update          on public.spaces        to authenticated;
grant select, delete          on public.space_members to authenticated;
grant select, insert, update, delete on public.records to authenticated;

-- 가족이 동시에 쓸 때 다른 기기에 바로 반영되도록 실시간 알림 켜기
do $$
begin
  alter publication supabase_realtime add table public.records;
exception when duplicate_object then null;
end $$;
