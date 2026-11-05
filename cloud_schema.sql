-- ============================================================================================
-- Design Studio — Cloud schema v3: Workspaces → Projects → Boards, comments & threads,
-- version history, activity log, in-app notifications
-- Run this ONCE in your Supabase project: Dashboard → SQL Editor → New query → paste all → Run.
-- Safe to re-run (it drops and recreates only its own policies/functions/triggers).
--
-- ONE-TIME SETUP (owner/admin only — nobody else ever needs a Supabase account):
--   1. supabase.com → sign up (free) → New project.
--   2. SQL Editor → paste this whole file → Run.
--   3. Authentication → URL Configuration:
--        Site URL       = https://dhirajkumarranchi-design.github.io/Zoning_Blocking_UX-Journey/
--        Redirect URLs  = add the same address
--   4. Authentication → Email Templates → "Magic Link": add this line to the message so people
--      can also sign in with a 6-digit code (needed inside Miro and on iPad):
--        <p>Or enter this code in Design Studio: <b>{{ .Token }}</b></p>
--   5. Project Settings → API → copy the "Project URL" and the "anon public" key and send them
--      over (NOT the "service_role" key — never share that one). They get built into the app,
--      so teammates only ever type their email.
--   6. OPTIONAL — email notifications (mentions, replies, invites): run cloud_email.sql too.
--      Its header explains the 10-minute Brevo setup (free, no domain needed).
--
-- WHO SEES WHAT
--   workspace member  → every project in the workspace (except private ones, unless owner)
--   project member    → only that project's boards (use this for clients / consultants)
--   roles             → owner (manage + edit) · editor (edit + save) · commenter (view + comment)
--                       · viewer (view only). A person's role on a project is the higher of their
--                       direct project role and their workspace role.
--   An invite works before the person has ever signed in; it attaches to them on first login.
-- ============================================================================================

create extension if not exists pgcrypto;

create table if not exists workspaces (
  id          uuid primary key default gen_random_uuid(),
  name        text not null check (length(name) between 1 and 120),
  owner       uuid not null default auth.uid() references auth.users on delete cascade,
  created_at  timestamptz not null default now()
);

create table if not exists workspace_members (
  workspace_id uuid not null references workspaces(id) on delete cascade,
  email        text not null check (email = lower(email)),
  user_id      uuid references auth.users on delete set null,
  role         text not null default 'editor' check (role in ('owner','editor','commenter','viewer')),
  invited_by   text,
  invited_at   timestamptz not null default now(),
  primary key (workspace_id, email)
);

create table if not exists projects (
  id           uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references workspaces(id) on delete cascade,
  name         text not null check (length(name) between 1 and 120),
  private      boolean not null default false,
  created_by   uuid default auth.uid() references auth.users on delete set null,
  created_at   timestamptz not null default now()
);

create table if not exists project_members (
  project_id  uuid not null references projects(id) on delete cascade,
  email       text not null check (email = lower(email)),
  user_id     uuid references auth.users on delete set null,
  role        text not null default 'viewer' check (role in ('owner','editor','commenter','viewer')),
  invited_by  text,
  invited_at  timestamptz not null default now(),
  primary key (project_id, email)
);

create table if not exists boards (
  id          uuid primary key default gen_random_uuid(),
  project_id  uuid not null references projects(id) on delete cascade,
  name        text not null default 'Untitled board' check (length(name) between 1 and 160),
  data        jsonb not null default '{}'::jsonb,
  updated_at  timestamptz not null default now(),
  updated_by  text
);

create table if not exists board_comments (
  id          uuid primary key default gen_random_uuid(),
  board_id    uuid not null references boards(id) on delete cascade,
  floor       int not null default 0,
  x           double precision not null,
  y           double precision not null,
  text        text not null check (length(text) between 1 and 4000),
  author      text not null default lower(coalesce(auth.jwt()->>'email','')),
  resolved    boolean not null default false,
  created_at  timestamptz not null default now()
);

create index if not exists projects_ws_idx on projects(workspace_id);
create index if not exists boards_project_idx on boards(project_id);
create index if not exists comments_board_idx on board_comments(board_id);
create index if not exists wm_email_idx on workspace_members(email);
create index if not exists pm_email_idx on project_members(email);

-- --------------------------------------------------------------------------------------------
-- Role helpers. SECURITY DEFINER so the policies below can look up membership without the
-- lookup itself being filtered by those same policies (which Postgres rejects as "infinite
-- recursion detected in policy").
-- --------------------------------------------------------------------------------------------
create or replace function my_email() returns text language sql stable as
$$ select lower(coalesce(auth.jwt()->>'email','')) $$;

create or replace function role_rank(r text) returns int language sql immutable as
$$ select case r when 'owner' then 4 when 'editor' then 3 when 'commenter' then 2 when 'viewer' then 1 else 0 end $$;

create or replace function ws_role(ws uuid) returns text
language sql stable security definer set search_path = public as
$$ select role from workspace_members where workspace_id = ws and email = my_email() $$;

-- effective project role = the higher of: direct project role, inherited workspace role
-- (a private project inherits only from the workspace OWNER)
create or replace function project_role(p uuid) returns text
language sql stable security definer set search_path = public as
$$
  select r from (
    select pm.role as r from project_members pm where pm.project_id = p and pm.email = my_email()
    union all
    select wm.role from projects pr
      join workspace_members wm on wm.workspace_id = pr.workspace_id and wm.email = my_email()
     where pr.id = p and (not pr.private or wm.role = 'owner')
  ) x order by role_rank(r) desc limit 1
$$;

-- a workspace is visible to its members, and (name only) to guests of any project inside it
create or replace function ws_visible(ws uuid) returns boolean
language sql stable security definer set search_path = public as
$$
  select exists (select 1 from workspace_members where workspace_id = ws and email = my_email())
      or exists (select 1 from projects p join project_members pm on pm.project_id = p.id
                  where p.workspace_id = ws and pm.email = my_email())
$$;

-- attach any invites for my email to my account (called by the app after every sign-in)
create or replace function claim_invites() returns void
language sql security definer set search_path = public as
$$
  update workspace_members set user_id = auth.uid() where email = my_email() and user_id is null;
  update project_members   set user_id = auth.uid() where email = my_email() and user_id is null;
$$;

grant execute on function my_email(), role_rank(text), ws_role(uuid), project_role(uuid), ws_visible(uuid), claim_invites() to authenticated;

-- creator of a workspace becomes its owner; creator of a project becomes that project's owner
create or replace function on_workspace_created() returns trigger
language plpgsql security definer set search_path = public as
$$ begin
  insert into workspace_members(workspace_id, email, user_id, role, invited_by)
  values (new.id, my_email(), new.owner, 'owner', my_email()) on conflict do nothing;
  return new;
end $$;
drop trigger if exists trg_workspace_created on workspaces;
create trigger trg_workspace_created after insert on workspaces for each row execute function on_workspace_created();

create or replace function on_project_created() returns trigger
language plpgsql security definer set search_path = public as
$$ begin
  insert into project_members(project_id, email, user_id, role, invited_by)
  values (new.id, my_email(), auth.uid(), 'owner', my_email()) on conflict do nothing;
  return new;
end $$;
drop trigger if exists trg_project_created on projects;
create trigger trg_project_created after insert on projects for each row execute function on_project_created();

-- keep boards.updated_at honest
create or replace function touch_board() returns trigger language plpgsql as
$$ begin new.updated_at = now(); new.updated_by = my_email(); return new; end $$;
drop trigger if exists trg_touch_board on boards;
create trigger trg_touch_board before insert or update on boards for each row execute function touch_board();

-- --------------------------------------------------------------------------------------------
-- Row Level Security
-- --------------------------------------------------------------------------------------------
alter table workspaces        enable row level security;
alter table workspace_members enable row level security;
alter table projects          enable row level security;
alter table project_members   enable row level security;
alter table boards            enable row level security;
alter table board_comments    enable row level security;

do $$ declare r record; begin
  for r in select policyname, tablename from pg_policies where schemaname = 'public'
    and tablename in ('workspaces','workspace_members','projects','project_members','boards','board_comments')
  loop execute format('drop policy %I on %I', r.policyname, r.tablename); end loop;
end $$;

-- workspaces
create policy ws_select on workspaces for select using (owner = auth.uid() or ws_visible(id));
create policy ws_insert on workspaces for insert with check (owner = auth.uid());
create policy ws_update on workspaces for update using (ws_role(id) = 'owner') with check (ws_role(id) = 'owner');
create policy ws_delete on workspaces for delete using (ws_role(id) = 'owner');

-- workspace members: members see the list; only owners add / change / remove; anyone may leave
create policy wm_select on workspace_members for select using (ws_role(workspace_id) is not null);
create policy wm_insert on workspace_members for insert with check (ws_role(workspace_id) = 'owner');
create policy wm_update on workspace_members for update using (ws_role(workspace_id) = 'owner') with check (ws_role(workspace_id) = 'owner');
create policy wm_delete on workspace_members for delete using (ws_role(workspace_id) = 'owner' or (email = my_email() and role <> 'owner'));

-- projects: workspace owners/editors create; project or workspace owners manage
create policy pr_select on projects for select using (project_role(id) is not null or (created_by = auth.uid() and ws_role(workspace_id) is not null));
create policy pr_insert on projects for insert with check (role_rank(ws_role(workspace_id)) >= 3 and created_by = auth.uid());
create policy pr_update on projects for update using (project_role(id) = 'owner' or ws_role(workspace_id) = 'owner') with check (project_role(id) = 'owner' or ws_role(workspace_id) = 'owner');
create policy pr_delete on projects for delete using (project_role(id) = 'owner' or ws_role(workspace_id) = 'owner');

-- project members: anyone on the project sees the list; project owners manage; anyone may leave
create policy pm_select on project_members for select using (project_role(project_id) is not null);
create policy pm_insert on project_members for insert with check (project_role(project_id) = 'owner');
create policy pm_update on project_members for update using (project_role(project_id) = 'owner') with check (project_role(project_id) = 'owner');
create policy pm_delete on project_members for delete using (project_role(project_id) = 'owner' or (email = my_email() and role <> 'owner'));

-- boards: anyone on the project reads; editors+ create and save; owners delete
create policy b_select on boards for select using (project_role(project_id) is not null);
create policy b_insert on boards for insert with check (role_rank(project_role(project_id)) >= 3);
create policy b_update on boards for update using (role_rank(project_role(project_id)) >= 3) with check (role_rank(project_role(project_id)) >= 3);
create policy b_delete on boards for delete using (project_role(project_id) = 'owner');

-- comments: anyone on the project reads; commenters+ post as themselves; authors or editors+ resolve/delete
create policy c_select on board_comments for select using (exists (select 1 from boards b where b.id = board_id and project_role(b.project_id) is not null));
create policy c_insert on board_comments for insert with check (author = my_email() and exists (select 1 from boards b where b.id = board_id and role_rank(project_role(b.project_id)) >= 2));
create policy c_update on board_comments for update using (author = my_email() or exists (select 1 from boards b where b.id = board_id and role_rank(project_role(b.project_id)) >= 3));
create policy c_delete on board_comments for delete using (author = my_email() or exists (select 1 from boards b where b.id = board_id and role_rank(project_role(b.project_id)) >= 3));

-- ============================================================================================
-- Stage 3: comment threads & @mentions, version history, activity log, notifications
-- ============================================================================================
alter table board_comments add column if not exists parent_id   uuid references board_comments(id) on delete cascade;
alter table board_comments add column if not exists mentions    text[] not null default '{}';
alter table board_comments add column if not exists resolved_by text;

create table if not exists board_versions (
  id          uuid primary key default gen_random_uuid(),
  board_id    uuid not null references boards(id) on delete cascade,
  data        jsonb not null,
  note        text check (note is null or length(note) <= 200),
  auto        boolean not null default false,
  created_by  text not null default lower(coalesce(auth.jwt()->>'email','')),
  created_at  timestamptz not null default now()
);
create index if not exists versions_board_idx on board_versions(board_id, created_at desc);

create table if not exists activity (
  id           bigserial primary key,
  workspace_id uuid references workspaces(id) on delete cascade,
  project_id   uuid references projects(id) on delete cascade,
  board_id     uuid references boards(id) on delete set null,
  actor        text not null,
  action       text not null,
  detail       text,
  created_at   timestamptz not null default now()
);
create index if not exists activity_ws_idx on activity(workspace_id, created_at desc);
create index if not exists activity_proj_idx on activity(project_id, created_at desc);

create table if not exists notifications (
  id           bigserial primary key,
  recipient    text not null,
  kind         text not null,
  message      text not null,
  workspace_id uuid references workspaces(id) on delete cascade,
  project_id   uuid references projects(id) on delete cascade,
  board_id     uuid references boards(id) on delete cascade,
  actor        text,
  read         boolean not null default false,
  created_at   timestamptz not null default now()
);
create index if not exists notif_recipient_idx on notifications(recipient, read, created_at desc);

-- role of ANY email on a project (same rule as project_role, for notifying other people)
create or replace function role_of(p uuid, who text) returns text
language sql stable security definer set search_path = public as
$$
  select r from (
    select pm.role as r from project_members pm where pm.project_id = p and pm.email = lower(who)
    union all
    select wm.role from projects pr join workspace_members wm on wm.workspace_id = pr.workspace_id and wm.email = lower(who)
     where pr.id = p and (not pr.private or wm.role = 'owner')
  ) x order by role_rank(r) desc limit 1
$$;

create or replace function log_activity(ws uuid, p uuid, b uuid, act text, det text) returns void
language sql security definer set search_path = public as
$$ insert into activity(workspace_id, project_id, board_id, actor, action, detail) values (ws, p, b, coalesce(nullif(my_email(),''),'system'), act, det) $$;

create or replace function notify(who text, k text, msg text, ws uuid, p uuid, b uuid) returns void
language sql security definer set search_path = public as
$$ insert into notifications(recipient, kind, message, workspace_id, project_id, board_id, actor)
   select lower(who), k, msg, ws, p, b, my_email() where lower(who) <> my_email() $$;

-- boards: automatic version every >=10 min of editing (keeps the last 100 automatic ones),
-- plus activity (edits throttled to one entry per person per board per 10 min)
create or replace function on_board_changed() returns trigger
language plpgsql security definer set search_path = public as
$$ declare ws uuid; begin
  select workspace_id into ws from projects where id = coalesce(new.project_id, old.project_id);
  if tg_op = 'INSERT' then
    perform log_activity(ws, new.project_id, new.id, 'created board', new.name);
  elsif tg_op = 'UPDATE' then
    if new.data is distinct from old.data then
      if not exists (select 1 from board_versions where board_id = old.id and created_at > now() - interval '10 minutes') then
        insert into board_versions(board_id, data, auto, created_by) values (old.id, old.data, true, coalesce(old.updated_by,''));
        delete from board_versions where id in (select id from board_versions where board_id = old.id and auto order by created_at desc offset 100);
      end if;
      if not exists (select 1 from activity where board_id = new.id and actor = my_email() and action = 'edited board' and created_at > now() - interval '10 minutes') then
        perform log_activity(ws, new.project_id, new.id, 'edited board', new.name);
      end if;
    end if;
    if new.name is distinct from old.name then perform log_activity(ws, new.project_id, new.id, 'renamed board', old.name || ' → ' || new.name); end if;
  elsif tg_op = 'DELETE' then
    perform log_activity(ws, old.project_id, null, 'deleted board', old.name);
  end if;
  return coalesce(new, old);
end $$;
drop trigger if exists trg_board_changed on boards;
create trigger trg_board_changed after insert or update or delete on boards for each row execute function on_board_changed();

create or replace function on_project_changed() returns trigger
language plpgsql security definer set search_path = public as
$$ begin
  if tg_op = 'INSERT' then perform log_activity(new.workspace_id, new.id, null, 'created project', new.name);
  elsif tg_op = 'UPDATE' then
    if new.private is distinct from old.private then perform log_activity(new.workspace_id, new.id, null, case when new.private then 'made project private' else 'made project visible to the workspace' end, new.name); end if;
    if new.name is distinct from old.name then perform log_activity(new.workspace_id, new.id, null, 'renamed project', old.name || ' → ' || new.name); end if;
  end if;
  return new;
end $$;
drop trigger if exists trg_project_changed on projects;
create trigger trg_project_changed after insert or update on projects for each row execute function on_project_changed();

-- membership changes -> activity + a notification to the person concerned
create or replace function on_member_changed() returns trigger
language plpgsql security definer set search_path = public as
$$ declare ws uuid; p uuid; nm text; r record; begin
  r := coalesce(new, old);
  if tg_table_name = 'workspace_members' then ws := r.workspace_id; p := null; select name into nm from workspaces where id = ws;
  else p := r.project_id; select workspace_id, name into ws, nm from projects where id = p; end if;
  if tg_op = 'INSERT' then
    if r.email <> my_email() then
      perform log_activity(ws, p, null, 'invited', r.email || ' as ' || r.role);
      perform notify(r.email, 'invite', my_email() || ' added you to ' || case when p is null then 'workspace' else 'project' end || ' “' || nm || '” as ' || r.role, ws, p, null);
    end if;
  elsif tg_op = 'UPDATE' and new.role is distinct from old.role then
    perform log_activity(ws, p, null, 'changed role', r.email || ': ' || old.role || ' → ' || new.role);
    perform notify(r.email, 'role', 'Your role on “' || nm || '” is now ' || new.role, ws, p, null);
  elsif tg_op = 'DELETE' then
    perform log_activity(ws, p, null, case when old.email = my_email() then 'left' else 'removed' end, old.email);
  end if;
  return r;
end $$;
drop trigger if exists trg_wm_changed on workspace_members;
create trigger trg_wm_changed after insert or update or delete on workspace_members for each row execute function on_member_changed();
drop trigger if exists trg_pm_changed on project_members;
create trigger trg_pm_changed after insert or update or delete on project_members for each row execute function on_member_changed();

-- comments: activity, @mention notifications (only people who can see the board), reply notification
create or replace function on_comment_changed() returns trigger
language plpgsql security definer set search_path = public as
$$ declare b record; ws uuid; who text; root_author text; begin
  select id, project_id, name into b from boards where id = new.board_id;
  select workspace_id into ws from projects where id = b.project_id;
  if tg_op = 'INSERT' then
    perform log_activity(ws, b.project_id, b.id, case when new.parent_id is null then 'commented' else 'replied' end, left(new.text, 120));
    foreach who in array coalesce(new.mentions, '{}') loop
      if role_of(b.project_id, who) is not null then
        perform notify(who, 'mention', new.author || ' mentioned you on “' || b.name || '”: ' || left(new.text, 140), ws, b.project_id, b.id);
      end if;
    end loop;
    if new.parent_id is not null then
      select author into root_author from board_comments where id = new.parent_id;
      if root_author is not null and not (lower(root_author) = any(coalesce(new.mentions,'{}'))) then
        perform notify(root_author, 'reply', new.author || ' replied on “' || b.name || '”: ' || left(new.text, 140), ws, b.project_id, b.id);
      end if;
    end if;
  elsif tg_op = 'UPDATE' and new.resolved is distinct from old.resolved then
    perform log_activity(ws, b.project_id, b.id, case when new.resolved then 'resolved comment' else 'reopened comment' end, left(new.text, 120));
    if new.resolved and new.author <> my_email() then perform notify(new.author, 'resolved', my_email() || ' resolved your comment: ' || left(new.text, 140), ws, b.project_id, b.id); end if;
  end if;
  return new;
end $$;
drop trigger if exists trg_comment_changed on board_comments;
create trigger trg_comment_changed after insert or update on board_comments for each row execute function on_comment_changed();

create or replace function on_version_saved() returns trigger
language plpgsql security definer set search_path = public as
$$ declare b record; ws uuid; begin
  if new.auto then return new; end if;
  select id, project_id, name into b from boards where id = new.board_id; select workspace_id into ws from projects where id = b.project_id;
  perform log_activity(ws, b.project_id, b.id, 'saved version', coalesce(new.note, b.name));
  return new;
end $$;
drop trigger if exists trg_version_saved on board_versions;
create trigger trg_version_saved after insert on board_versions for each row execute function on_version_saved();

-- restore a past version (editors+): the current state is kept as a version first, so a restore
-- can itself be undone
create or replace function restore_version(v uuid) returns void
language plpgsql security definer set search_path = public as
$$ declare ver record; b record; begin
  select * into ver from board_versions where id = v;
  if ver is null then raise exception 'version not found'; end if;
  select * into b from boards where id = ver.board_id;
  if role_rank(project_role(b.project_id)) < 3 then raise exception 'only editors can restore versions'; end if;
  insert into board_versions(board_id, data, note, auto, created_by) values (b.id, b.data, 'Before restoring ' || to_char(ver.created_at, 'DD Mon HH24:MI'), false, my_email());
  update boards set data = ver.data where id = b.id;
  perform log_activity((select workspace_id from projects where id = b.project_id), b.project_id, b.id, 'restored version', coalesce(ver.note, to_char(ver.created_at, 'DD Mon YYYY HH24:MI')));
end $$;

grant execute on function role_of(uuid, text), restore_version(uuid) to authenticated;
revoke execute on function log_activity(uuid, uuid, uuid, text, text), notify(text, text, text, uuid, uuid, uuid) from public, authenticated;

alter table board_versions enable row level security;
alter table activity       enable row level security;
alter table notifications  enable row level security;
do $$ declare r record; begin
  for r in select policyname, tablename from pg_policies where schemaname = 'public' and tablename in ('board_versions','activity','notifications')
  loop execute format('drop policy %I on %I', r.policyname, r.tablename); end loop;
end $$;

create policy v_select on board_versions for select using (exists (select 1 from boards b where b.id = board_id and project_role(b.project_id) is not null));
create policy v_insert on board_versions for insert with check (auto = false and created_by = my_email() and exists (select 1 from boards b where b.id = board_id and role_rank(project_role(b.project_id)) >= 3));
create policy v_delete on board_versions for delete using (exists (select 1 from boards b where b.id = board_id and project_role(b.project_id) = 'owner'));

-- activity: project rows to anyone on the project; workspace-level rows to workspace members
create policy a_select on activity for select using ((project_id is not null and project_role(project_id) is not null) or (project_id is null and ws_role(workspace_id) is not null));

-- notifications: only your own; you can mark them read or delete them
create policy n_select on notifications for select using (recipient = my_email());
create policy n_update on notifications for update using (recipient = my_email()) with check (recipient = my_email());
create policy n_delete on notifications for delete using (recipient = my_email());

-- comment threads: replies must sit on a comment of the same board
create or replace function check_reply() returns trigger language plpgsql as
$$ begin
  if new.parent_id is not null and not exists (select 1 from board_comments c where c.id = new.parent_id and c.board_id = new.board_id and c.parent_id is null) then
    raise exception 'a reply must belong to a top-level comment on the same board';
  end if;
  new.mentions := coalesce((select array_agg(distinct lower(m)) from unnest(new.mentions) m), '{}');
  return new;
end $$;
drop trigger if exists trg_check_reply on board_comments;
create trigger trg_check_reply before insert on board_comments for each row execute function check_reply();
