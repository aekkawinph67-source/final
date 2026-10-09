-- ============================================================================
-- setup.sql  |  คอร์สแวร์ความจริงเสริมเพื่อการเรียนรู้  |  รันทั้งไฟล์ใน Supabase SQL Editor
-- รันซ้ำได้ (ใช้ if not exists / drop policy if exists)
-- ยังไม่ได้ทดสอบกับโปรเจกต์ Supabase จริง
--
-- วิธีป้องกันที่ใช้ (สรุป)
--  1) เปิด RLS ทุกตาราง + revoke all จาก anon และ authenticated แล้ว grant เท่าที่จำเป็น
--  2) ผู้เรียนแก้ students ได้เฉพาะคอลัมน์ photo_path (สิทธิ์ระดับคอลัมน์ + นโยบาย)
--  3) submissions: ผู้เรียนไม่มีสิทธิ์ INSERT คอลัมน์ score/teacher_comment (column grant),
--     ไม่มีนโยบาย UPDATE สำหรับผู้เรียน, และนโยบาย INSERT บังคับให้ score/teacher_comment เป็น null
--     เฉพาะผู้สอน (is_teacher()) เท่านั้นที่ UPDATE ได้ และได้เฉพาะสองคอลัมน์นี้
-- ============================================================================

-- ---------- 1) ตาราง ----------
create table if not exists public.teachers (
  user_id uuid primary key references auth.users(id) on delete cascade
);

create table if not exists public.students (
  id          text primary key check (id ~ '^[0-9]{11}$'),
  title       text,
  first_name  text not null,
  last_name   text not null,
  section     text,
  user_id     uuid unique references auth.users(id) on delete set null,
  photo_path  text,
  constraint students_photo_owner check (
    photo_path is null or (user_id is not null and photo_path like user_id::text || '/%')
  )
);

create table if not exists public.attempts (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references auth.users(id) on delete cascade,
  kind        text not null check (kind in ('pre','post')),
  score       integer not null check (score between 0 and 10),
  answers     jsonb,
  created_at  timestamptz not null default now(),
  unique (user_id, kind)
);

create table if not exists public.progress (
  user_id uuid not null references auth.users(id) on delete cascade,
  unit    integer not null check (unit between 1 and 5),
  done    boolean not null default true,
  primary key (user_id, unit)
);

create table if not exists public.submissions (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid not null references auth.users(id) on delete cascade,
  unit            integer not null default 4 check (unit between 1 and 5),
  kind            text not null check (kind in ('link','file')),
  url             text check (url is null or char_length(url) <= 2000),
  storage_path    text,
  note            text check (note is null or char_length(note) <= 500),
  score           numeric(4,1) check (score is null or (score >= 0 and score <= 10)),
  teacher_comment text check (teacher_comment is null or char_length(teacher_comment) <= 1000),
  created_at      timestamptz not null default now(),
  constraint submissions_shape check (
    (kind = 'link' and url ~* '^https?://' and storage_path is null) or
    (kind = 'file' and storage_path is not null and url is null)
  ),
  constraint submissions_path_owner check (
    storage_path is null or storage_path like user_id::text || '/%'
  )
);

create table if not exists public.materials (
  id            uuid primary key default gen_random_uuid(),
  title         text not null check (char_length(title) <= 200),
  kind          text not null check (kind in ('file','link','video')),
  url           text check (url is null or char_length(url) <= 2000),
  storage_path  text,
  file_name     text check (file_name is null or char_length(file_name) <= 255),
  created_at    timestamptz not null default now(),
  constraint materials_shape check (
    (kind = 'file' and storage_path is not null) or
    (kind in ('link','video') and url ~* '^https?://')
  )
);

-- ---------- 2) ฟังก์ชันตรวจผู้สอน ----------
create or replace function public.is_teacher()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.teachers t where t.user_id = (select auth.uid())
  );
$$;
revoke all on function public.is_teacher() from public, anon;
grant execute on function public.is_teacher() to authenticated;

-- ---------- 3) trigger ผูกบัญชีผู้เรียนกับรายชื่อ ----------
-- อีเมลที่ส่วนหน้า @ เป็นเลข 11 หลัก = ผู้เรียน ต้องมีรหัสในรายชื่อและยังไม่ถูกใช้
-- อีเมลอื่น (ผู้สอน) ข้ามไป
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  sid text;
begin
  if new.email is null then
    return new;
  end if;
  sid := split_part(new.email, '@', 1);
  if sid !~ '^[0-9]{11}$' then
    return new;
  end if;
  update public.students
     set user_id = new.id
   where id = sid and user_id is null;
  if not found then
    raise exception 'student_not_eligible';
  end if;
  return new;
end;
$$;
revoke all on function public.handle_new_user() from public, anon, authenticated;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------- 4) เปิด RLS + ตั้งสิทธิ์ระดับตาราง/คอลัมน์ ----------
alter table public.teachers    enable row level security;
alter table public.students    enable row level security;
alter table public.attempts    enable row level security;
alter table public.progress    enable row level security;
alter table public.submissions enable row level security;
alter table public.materials   enable row level security;

revoke all on table public.teachers, public.students, public.attempts,
                    public.progress, public.submissions, public.materials
  from anon, authenticated;

grant select on public.teachers to authenticated;

grant select on public.students to authenticated;
grant update (photo_path) on public.students to authenticated;      -- ผู้เรียนแก้ได้เฉพาะคอลัมน์นี้

grant select on public.attempts to authenticated;
grant insert (user_id, kind, score, answers) on public.attempts to authenticated;

grant select on public.progress to authenticated;
grant insert (user_id, unit, done) on public.progress to authenticated;
grant update (done) on public.progress to authenticated;

grant select on public.submissions to authenticated;
grant insert (user_id, unit, kind, url, storage_path, note) on public.submissions to authenticated;
grant update (score, teacher_comment) on public.submissions to authenticated;  -- ใช้ได้เฉพาะผู้สอนผ่านนโยบาย
grant delete on public.submissions to authenticated;

grant select on public.materials to authenticated;
grant insert (title, kind, url, storage_path, file_name) on public.materials to authenticated;
grant delete on public.materials to authenticated;

-- ---------- 5) นโยบาย RLS ----------
-- teachers
drop policy if exists teachers_select_own on public.teachers;
create policy teachers_select_own on public.teachers
  for select to authenticated using (user_id = (select auth.uid()));

-- students (การเพิ่ม/ลบรายชื่อทำผ่าน Table Editor ด้วยสิทธิ์เจ้าของโปรเจกต์ จึงไม่มีนโยบาย insert/delete)
drop policy if exists students_select_own on public.students;
create policy students_select_own on public.students
  for select to authenticated using (user_id = (select auth.uid()));

drop policy if exists students_select_teacher on public.students;
create policy students_select_teacher on public.students
  for select to authenticated using (public.is_teacher());

drop policy if exists students_update_own on public.students;
create policy students_update_own on public.students
  for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

-- attempts: ทำได้ครั้งเดียวต่อชุด (unique) / หลังเรียนต้องมีก่อนเรียนและเรียนครบ 5 หน่วย
drop policy if exists attempts_select_own on public.attempts;
create policy attempts_select_own on public.attempts
  for select to authenticated using (user_id = (select auth.uid()));

drop policy if exists attempts_select_teacher on public.attempts;
create policy attempts_select_teacher on public.attempts
  for select to authenticated using (public.is_teacher());

drop policy if exists attempts_insert_own on public.attempts;
create policy attempts_insert_own on public.attempts
  for insert to authenticated
  with check (
    user_id = (select auth.uid())
    and (
      kind = 'pre'
      or (
        exists (select 1 from public.attempts a
                where a.user_id = (select auth.uid()) and a.kind = 'pre')
        and (select count(*) from public.progress p
             where p.user_id = (select auth.uid()) and p.done) = 5
      )
    )
  );

-- progress
drop policy if exists progress_select_own on public.progress;
create policy progress_select_own on public.progress
  for select to authenticated using (user_id = (select auth.uid()));

drop policy if exists progress_select_teacher on public.progress;
create policy progress_select_teacher on public.progress
  for select to authenticated using (public.is_teacher());

drop policy if exists progress_insert_own on public.progress;
create policy progress_insert_own on public.progress
  for insert to authenticated with check (user_id = (select auth.uid()));

drop policy if exists progress_update_own on public.progress;
create policy progress_update_own on public.progress
  for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

-- submissions
drop policy if exists submissions_select_own on public.submissions;
create policy submissions_select_own on public.submissions
  for select to authenticated using (user_id = (select auth.uid()));

drop policy if exists submissions_select_teacher on public.submissions;
create policy submissions_select_teacher on public.submissions
  for select to authenticated using (public.is_teacher());

drop policy if exists submissions_insert_own on public.submissions;
create policy submissions_insert_own on public.submissions
  for insert to authenticated
  with check (
    user_id = (select auth.uid())
    and score is null
    and teacher_comment is null
  );

drop policy if exists submissions_update_teacher on public.submissions;
create policy submissions_update_teacher on public.submissions
  for update to authenticated
  using (public.is_teacher())
  with check (public.is_teacher());

drop policy if exists submissions_delete_own_ungraded on public.submissions;
create policy submissions_delete_own_ungraded on public.submissions
  for delete to authenticated
  using (user_id = (select auth.uid()) and score is null);

-- materials
drop policy if exists materials_select_all on public.materials;
create policy materials_select_all on public.materials
  for select to authenticated using (true);

drop policy if exists materials_insert_teacher on public.materials;
create policy materials_insert_teacher on public.materials
  for insert to authenticated with check (public.is_teacher());

drop policy if exists materials_delete_teacher on public.materials;
create policy materials_delete_teacher on public.materials
  for delete to authenticated using (public.is_teacher());

-- ---------- 6) มุมมอง results (security_invoker: ใช้ RLS ของผู้เรียกใช้) ----------
create or replace view public.results
with (security_invoker = true) as
select
  s.id,
  s.title,
  s.first_name,
  s.last_name,
  s.section,
  s.user_id,
  (s.user_id is not null) as registered,
  s.photo_path,
  coalesce((select count(*) from public.progress p
            where p.user_id = s.user_id and p.done), 0)::int as units_done,
  pre.score  as pre_score,
  post.score as post_score,
  case
    when pre.score is not null and post.score is not null and pre.score < 10
    then round((post.score - pre.score)::numeric / (10 - pre.score), 2)
  end as gain
from public.students s
left join public.attempts pre  on pre.user_id  = s.user_id and pre.kind  = 'pre'
left join public.attempts post on post.user_id = s.user_id and post.kind = 'post';

revoke all on public.results from anon, authenticated;
grant select on public.results to authenticated;

-- ---------- 7) Storage: bucket แบบ private ----------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types) values
  ('photos', 'photos', false, 2097152,
     array['image/png','image/jpeg']),
  ('submissions', 'submissions', false, 20971520,
     array['image/png','image/jpeg','application/pdf','video/mp4']),
  ('materials', 'materials', false, 52428800,
     array['application/vnd.openxmlformats-officedocument.presentationml.presentation',
           'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
           'application/pdf'])
on conflict (id) do update
  set public = false,
      file_size_limit = excluded.file_size_limit,
      allowed_mime_types = excluded.allowed_mime_types;

-- นโยบาย storage.objects: photos
drop policy if exists photos_select on storage.objects;
create policy photos_select on storage.objects for select to authenticated
  using (bucket_id = 'photos'
         and ((storage.foldername(name))[1] = (select auth.uid())::text or public.is_teacher()));

drop policy if exists photos_insert on storage.objects;
create policy photos_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'photos'
              and (storage.foldername(name))[1] = (select auth.uid())::text);

drop policy if exists photos_update on storage.objects;
create policy photos_update on storage.objects for update to authenticated
  using (bucket_id = 'photos' and (storage.foldername(name))[1] = (select auth.uid())::text)
  with check (bucket_id = 'photos' and (storage.foldername(name))[1] = (select auth.uid())::text);

drop policy if exists photos_delete on storage.objects;
create policy photos_delete on storage.objects for delete to authenticated
  using (bucket_id = 'photos' and (storage.foldername(name))[1] = (select auth.uid())::text);

-- นโยบาย storage.objects: submissions
drop policy if exists submissions_select on storage.objects;
create policy submissions_select on storage.objects for select to authenticated
  using (bucket_id = 'submissions'
         and ((storage.foldername(name))[1] = (select auth.uid())::text or public.is_teacher()));

drop policy if exists submissions_insert on storage.objects;
create policy submissions_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'submissions'
              and (storage.foldername(name))[1] = (select auth.uid())::text);

drop policy if exists submissions_update on storage.objects;
create policy submissions_update on storage.objects for update to authenticated
  using (bucket_id = 'submissions' and (storage.foldername(name))[1] = (select auth.uid())::text)
  with check (bucket_id = 'submissions' and (storage.foldername(name))[1] = (select auth.uid())::text);

drop policy if exists submissions_delete on storage.objects;
create policy submissions_delete on storage.objects for delete to authenticated
  using (bucket_id = 'submissions' and (storage.foldername(name))[1] = (select auth.uid())::text);

-- นโยบาย storage.objects: materials (ทุกคนที่ล็อกอินอ่านได้ ผู้สอนเขียนได้)
drop policy if exists materials_obj_select on storage.objects;
create policy materials_obj_select on storage.objects for select to authenticated
  using (bucket_id = 'materials');

drop policy if exists materials_obj_insert on storage.objects;
create policy materials_obj_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'materials' and public.is_teacher());

drop policy if exists materials_obj_update on storage.objects;
create policy materials_obj_update on storage.objects for update to authenticated
  using (bucket_id = 'materials' and public.is_teacher())
  with check (bucket_id = 'materials' and public.is_teacher());

drop policy if exists materials_obj_delete on storage.objects;
create policy materials_obj_delete on storage.objects for delete to authenticated
  using (bucket_id = 'materials' and public.is_teacher());

-- ---------- 8) รายชื่อผู้เรียน: ข้อมูลจำลอง 6 แถวเท่านั้น ----------
-- นำเข้ารายชื่อจริง: Table Editor > students > ลบแถวจำลอง > Insert > Import data from CSV
-- หัวคอลัมน์ CSV: id,title,first_name,last_name,section   (id = รหัสนักศึกษา 11 หลัก เป็นข้อความ)
-- ปล่อย user_id และ photo_path ว่างไว้
insert into public.students (id, title, first_name, last_name, section) values
  ('66000000001', 'นางสาว', 'ตัวอย่าง', 'หนึ่ง',  '1'),
  ('66000000002', 'นาย',    'ตัวอย่าง', 'สอง',    '1'),
  ('66000000003', 'นางสาว', 'ตัวอย่าง', 'สาม',    '1'),
  ('66000000004', 'นาย',    'ตัวอย่าง', 'สี่',    '2'),
  ('66000000005', 'นางสาว', 'ตัวอย่าง', 'ห้า',    '2'),
  ('66000000006', 'นาย',    'ตัวอย่าง', 'หก',     '2')
on conflict (id) do nothing;

-- ---------- 9) ตั้งผู้สอน (ปิดไว้ ให้ผู้สอนแก้อีเมลแล้วเปิดใช้เอง) ----------
-- ขั้นก่อนหน้า: Authentication > Users > Add user > Create new user (ติ๊ก Auto Confirm User)
-- แล้วเอาเครื่องหมายคอมเมนต์ออก แก้อีเมล แล้วรันเฉพาะคำสั่งนี้
/*
insert into public.teachers (user_id)
select id from auth.users where email = 'teacher@your-institution.ac.th'
on conflict do nothing;
*/
