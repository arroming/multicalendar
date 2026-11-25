-- =========================================================
-- 멀티 캘린더 · 추가 SQL 002: 프로필 그림 (8가지 중 1개)
-- schema.sql 을 이미 실행한 프로젝트에서 이 파일만 실행하면 됩니다.
-- SQL Editor → New query → 전체 붙여넣기 → Run. 여러 번 실행해도 안전하며 기존 기록은 지워지지 않습니다.
-- 그림 이름: sun, moon, cloud, rain, bolt, snow, rainbow, star
-- =========================================================

alter table public.profiles add column if not exists avatar text;

create or replace function public.valid_avatar(p text) returns text
language sql immutable as $$
  select case when p in ('sun','moon','cloud','rain','bolt','snow','rainbow','star') then p end;
$$;

-- 가족 등록: 이름 + 숫자 4자리 + 프로필 그림
drop function if exists public.register(text, text);
create or replace function public.register(p_name text, p_pin text, p_avatar text default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_name text := btrim(coalesce(p_name, ''));
  v_avatar text := public.valid_avatar(p_avatar);
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

  insert into public.profiles (space_id, name, pin_hash, avatar)
    values (sid, v_name, extensions.crypt(p_pin, extensions.gen_salt('bf')), v_avatar)
    returning id into pid;
  perform public.link_device(pid);
  return jsonb_build_object('profile_id', pid, 'name', v_name, 'space_id', sid, 'avatar', v_avatar);
end $$;

-- 로그인 (결과에 프로필 그림 포함)
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
  return jsonb_build_object('profile_id', pr.id, 'name', pr.name, 'space_id', pr.space_id, 'avatar', pr.avatar);
end $$;

create or replace function public.whoami() returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object('profile_id', p.id, 'name', p.name, 'space_id', p.space_id, 'avatar', p.avatar)
  from public.device_links d join public.profiles p on p.id = d.profile_id
  where d.user_id = auth.uid();
$$;

drop function if exists public.family_members();
create function public.family_members() returns table (id uuid, name text, avatar text)
language sql stable security definer set search_path = public as $$
  select p.id, p.name, p.avatar from public.profiles p
  where public.is_member(p.space_id)
  order by p.created_at;
$$;

-- 내 프로필 그림 바꾸기
create or replace function public.set_avatar(p_avatar text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v text := public.valid_avatar(p_avatar); pid uuid;
begin
  select profile_id into pid from public.device_links where user_id = auth.uid();
  if pid is null then return jsonb_build_object('error', 'not_signed_in'); end if;
  if v is null then return jsonb_build_object('error', 'bad_avatar'); end if;
  update public.profiles set avatar = v where id = pid;
  return jsonb_build_object('avatar', v);
end $$;

revoke execute on function public.register(text, text, text) from public, anon;
revoke execute on function public.family_members()           from public, anon;
revoke execute on function public.set_avatar(text)           from public, anon;
grant  execute on function public.register(text, text, text) to authenticated;
grant  execute on function public.login(text, text)          to authenticated;
grant  execute on function public.whoami()                   to authenticated;
grant  execute on function public.family_members()           to authenticated;
grant  execute on function public.set_avatar(text)           to authenticated;
