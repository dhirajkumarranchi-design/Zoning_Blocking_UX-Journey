-- ============================================================================================
-- Design Studio — Cloud schema v2: Workspaces → Projects → Boards (+ comments)
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
