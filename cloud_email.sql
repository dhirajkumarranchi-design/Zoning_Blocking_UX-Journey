-- ============================================================================================
-- Design Studio — OPTIONAL add-on: email notifications
-- Emails people when they are @mentioned, get a reply, have a comment resolved, or are invited
-- (the same events that already show in the 🔔 bell). Run it AFTER cloud_schema.sql.
--
-- It uses Brevo's free plan (300 emails a day). No domain is needed: you verify one sender
-- address (your Gmail is fine) and every email comes "from" it.
--
-- ONE-TIME SETUP (owner only, about 10 minutes):
--   1. brevo.com → sign up (free).
--   2. Brevo → Senders, Domains & Dedicated IPs → Senders → Add a sender → your email address
--      → open the confirmation email Brevo sends you and confirm it.
--   3. Brevo → SMTP & API → API Keys → Generate a new API key → copy it (starts with xkeysib-).
--   4. Supabase → SQL Editor → New query → paste this whole file.
--   5. In the "YOUR SETTINGS" block just below, replace the three values → Run.
--   Keep the API key private. It is stored encrypted in Supabase Vault — never in the app.
--
-- To change the key or the sender later: edit the same block and Run the file again.
-- To pause all emails:   update email_settings set enabled = false;
-- Each person can switch their own emails off in the app: 🔔 → "Email me".
-- See what was sent:      select * from email_log order by id desc limit 20;
-- See Brevo's answers:    select id, status_code, content from net._http_response order by id desc limit 10;
-- ============================================================================================

-- ------------------------------ YOUR SETTINGS ---------------------------------------------
do $settings$
declare
  brevo_api_key text := 'PASTE-YOUR-BREVO-API-KEY-HERE';
  sender_email  text := 'you@gmail.com';            -- the sender you verified in Brevo
  app_url       text := 'https://dhirajkumarranchi-design.github.io/Zoning_Blocking_UX-Journey/';
begin
  perform set_config('ds.brevo_api_key', brevo_api_key, false);
  perform set_config('ds.sender_email', sender_email, false);
  perform set_config('ds.app_url', app_url, false);
end $settings$;
-- -------------------------------------------------------------------------------------------

create extension if not exists pg_net;

-- settings: one row, readable only from the SQL editor (row level security on, no policies)
create table if not exists email_settings (
  id           int primary key default 1 check (id = 1),
  sender_email text not null,
  sender_name  text not null default 'Design Studio',
  app_url      text not null,
  enabled      boolean not null default true,
  per_hour     int not null default 20          -- at most this many emails per person per hour
);
alter table email_settings enable row level security;

-- each person's own choice (no row = default: on, for all four kinds)
create table if not exists email_prefs (
  email      text primary key,
  enabled    boolean not null default true,
  kinds      text[] not null default array['invite','mention','reply','resolved'],
  updated_at timestamptz not null default now()
);
alter table email_prefs enable row level security;
drop policy if exists email_prefs_own on email_prefs;
create policy email_prefs_own on email_prefs for all to authenticated
  using (email = my_email()) with check (email = my_email());
grant select, insert, update, delete on email_prefs to authenticated;

create table if not exists email_log (
  id              bigserial primary key,
  notification_id bigint,
  recipient       text not null,
  kind            text,
  status          text,
  request_id      bigint,
  created_at      timestamptz not null default now()
);
create index if not exists email_log_recent_idx on email_log(recipient, created_at desc);
alter table email_log enable row level security;
drop policy if exists email_log_own on email_log;
create policy email_log_own on email_log for select to authenticated using (recipient = my_email());
grant select on email_log to authenticated;

-- store the settings + key (the key goes to Vault, encrypted)
do $store$
declare k text := current_setting('ds.brevo_api_key', true); sid uuid;
begin
  insert into email_settings(id, sender_email, app_url)
  values (1, current_setting('ds.sender_email', true), current_setting('ds.app_url', true))
  on conflict (id) do update set sender_email = excluded.sender_email, app_url = excluded.app_url;
  if k is not null and k not like 'PASTE-%' then
    select id into sid from vault.secrets where name = 'brevo_api_key';
    if sid is null then perform vault.create_secret(k, 'brevo_api_key', 'Design Studio email notifications');
    else perform vault.update_secret(sid, k); end if;
  end if;
end $store$;

create or replace function email_html_escape(t text) returns text language sql immutable as
$$ select replace(replace(replace(coalesce(t,''), '&', '&amp;'), '<', '&lt;'), '>', '&gt;') $$;

-- one email per new notification (never blocks the notification itself: any problem is logged)
create or replace function email_on_notification() returns trigger
language plpgsql security definer set search_path = public as $$
declare s email_settings; pr email_prefs; k text; n int; link text; subj text; html text; rid bigint;
begin
  select * into s from email_settings where id = 1;
  if not found or not s.enabled then return new; end if;
  select * into pr from email_prefs where email = new.recipient;
  if found then
    if not pr.enabled or not (new.kind = any(pr.kinds)) then return new; end if;
  elsif new.kind not in ('invite','mention','reply','resolved') then return new;
  end if;
  select count(*) into n from email_log where recipient = new.recipient and status = 'sent' and created_at > now() - interval '1 hour';
  if n >= s.per_hour then
    insert into email_log(notification_id, recipient, kind, status) values (new.id, new.recipient, new.kind, 'skipped: hourly limit');
    return new;
  end if;
  select decrypted_secret into k from vault.decrypted_secrets where name = 'brevo_api_key' limit 1;
  if k is null then
    insert into email_log(notification_id, recipient, kind, status) values (new.id, new.recipient, new.kind, 'skipped: no API key set');
    return new;
  end if;
  link := s.app_url || '?ws=' || coalesce(new.workspace_id::text, '') || '&project=' || coalesce(new.project_id::text, '')
          || '&board=' || coalesce(new.board_id::text, '');
  subj := case new.kind when 'mention' then 'You were mentioned' when 'reply' then 'New reply to your comment'
                        when 'resolved' then 'Your comment was resolved' when 'invite' then 'You''ve been invited'
                        else 'Update' end || ' — Design Studio';
  html := '<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#222;line-height:1.5">'
       || '<p>' || email_html_escape(new.message) || '</p>'
       || '<p><a href="' || link || '" style="display:inline-block;background:#c8995a;color:#fff;padding:9px 16px;border-radius:6px;text-decoration:none">Open in Design Studio</a></p>'
       || case when new.kind = 'invite' then '<p style="color:#555">Sign in with this email address — no password, you''ll get a sign-in code.</p>' else '' end
       || '<p style="color:#888;font-size:12px">You get these because you''re on a Design Studio project. To stop them: open Design Studio → 🔔 → untick “Email me”.</p></div>';
  select net.http_post(
           url     := 'https://api.brevo.com/v3/smtp/email',
           body    := jsonb_build_object(
                        'sender', jsonb_build_object('name', s.sender_name, 'email', s.sender_email),
                        'to', jsonb_build_array(jsonb_build_object('email', new.recipient)),
                        'subject', subj, 'htmlContent', html),
           headers := jsonb_build_object('api-key', k, 'content-type', 'application/json', 'accept', 'application/json')
         ) into rid;
  insert into email_log(notification_id, recipient, kind, status, request_id) values (new.id, new.recipient, new.kind, 'sent', rid);
  return new;
exception when others then
  begin
    insert into email_log(notification_id, recipient, kind, status) values (new.id, new.recipient, new.kind, 'error: ' || sqlerrm);
  exception when others then null;
  end;
  return new;
end $$;
revoke all on function email_on_notification() from public, authenticated;

drop trigger if exists email_on_notification on notifications;
create trigger email_on_notification after insert on notifications
  for each row execute function email_on_notification();
