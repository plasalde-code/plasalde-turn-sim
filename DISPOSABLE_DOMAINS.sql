-- ============================================================================
--  Block disposable / throwaway email domains at SIGNUP  (server-side)
--  P.Lasalde Turn Simulator
-- ============================================================================
--
--  WHY THIS EXISTS
--  The check in signup.html is client-side: it gives the user immediate
--  feedback, but anyone can bypass it by calling the Supabase API directly.
--  This hook runs inside Supabase BEFORE the user row is created, so it
--  cannot be bypassed — it is the real enforcement.
--
--  HOW TO INSTALL  (about 2 minutes, one time)
--  1. Supabase Dashboard -> SQL Editor -> New query
--  2. Paste this whole file, click Run
--  3. Dashboard -> Authentication -> Hooks (Beta)
--  4. Enable "Before User Created", choose Postgres function,
--     select  public.block_disposable_email
--  5. Save. Test by signing up with  test@mailinator.com  (should be refused)
--
--  TO ADD A DOMAIN LATER
--  Just insert it:
--      insert into public.disposable_domains(domain) values ('newjunk.com');
--  No redeploy needed — the hook reads the table live.
--  (Also add it to DISPOSABLE_DOMAINS in signup.html so the user gets the
--   nicer inline error instead of a generic API failure.)
-- ============================================================================


-- ── 1. Table of blocked domains ─────────────────────────────────────────────
create table if not exists public.disposable_domains (
  domain text primary key
);

alter table public.disposable_domains enable row level security;
-- No policies = no client access. Only the auth admin (below) can read it.


-- ── 2. Seed the list ────────────────────────────────────────────────────────
insert into public.disposable_domains(domain) values
('0-mail.com'),('10minutemail.com'),('10minutemail.net'),('1secmail.com'),
('1secmail.net'),('1secmail.org'),('20minutemail.com'),('33mail.com'),
('anonbox.net'),('anonymbox.com'),('armyspy.com'),('bccto.me'),
('burnermail.io'),('byom.de'),('cock.li'),('courriel.fr.nf'),('cuvox.de'),
('dayrep.com'),('discard.email'),('discardmail.com'),('dispostable.com'),
('dodgit.com'),('dropmail.me'),('e4ward.com'),('einrot.com'),
('emailondeck.com'),('emailtemporanea.net'),('emltmp.com'),('fakeinbox.com'),
('fakemail.net'),('fleckens.hu'),('getairmail.com'),('getnada.com'),('grr.la'),
('guerrillamail.biz'),('guerrillamail.com'),('guerrillamail.de'),
('guerrillamail.net'),('guerrillamail.org'),('guerrillamailblock.com'),
('harakirimail.com'),('inboxalias.com'),('inboxbear.com'),('incognitomail.com'),
('jetable.org'),('koszmail.pl'),('linshiyouxiang.net'),('luxusmail.org'),
('mail-temporaire.fr'),('mail.tm'),('mail7.io'),('mailbox52.ga'),
('mailcatch.com'),('maildrop.cc'),('mailexpire.com'),('mailinator.com'),
('mailinator.net'),('mailnesia.com'),('mailnull.com'),('mailsac.com'),
('mailtemp.info'),('mailtothis.com'),('meltmail.com'),('mintemail.com'),
('moakt.com'),('mohmal.com'),('mt2015.com'),('mvrht.com'),('mytemp.email'),
('nada.email'),('no-spam.ws'),('nowmymail.com'),('objectmail.com'),
('onldm.net'),('owlpic.com'),('pokemail.net'),('proxymail.eu'),('rcpt.at'),
('rtrtr.com'),('safe-mail.net'),('sharklasers.com'),('shitmail.me'),
('sofimail.com'),('spam4.me'),('spamavert.com'),('spambog.com'),('spambox.us'),
('spamfree24.org'),('spamgourmet.com'),('spamhole.com'),('spaml.de'),
('superrito.com'),('tempail.com'),('tempemail.net'),('tempinbox.com'),
('tempmail.com'),('tempmail.de'),('tempmail.net'),('tempmailaddress.com'),
('tempmailer.com'),('tempr.email'),('temp-mail.io'),('temp-mail.org'),
('throwawaymail.com'),('tmpmail.net'),('tmpmail.org'),('trash-mail.com'),
('trashmail.com'),('trashmail.de'),('trashmail.me'),('trashmail.net'),
('trbvm.com'),('uroid.com'),('vomoto.com'),('wegwerfmail.de'),
('wegwerfmail.net'),('yopmail.com'),('yopmail.fr'),('yopmail.net'),
('zetmail.com')
on conflict (domain) do nothing;


-- ── 3. The hook function ────────────────────────────────────────────────────
-- Refuses signup when the address uses a listed domain. Also catches
-- subdomains (e.g. anything.mailinator.com) by walking the domain suffixes.
create or replace function public.block_disposable_email(event jsonb)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_email  text;
  v_domain text;
  v_parts  text[];
  i        int;
begin
  v_email := lower(trim(event -> 'user' ->> 'email'));

  -- No email (e.g. OAuth-only signup) -> nothing to check, allow.
  if v_email is null or position('@' in v_email) = 0 then
    return '{}'::jsonb;
  end if;

  v_domain := rtrim(split_part(v_email, '@', 2), '.');
  if v_domain = '' then
    return '{}'::jsonb;
  end if;

  -- Check the full domain and every parent suffix.
  v_parts := string_to_array(v_domain, '.');
  for i in 1 .. array_length(v_parts, 1) - 1 loop
    if exists (
      select 1 from public.disposable_domains
      where domain = array_to_string(v_parts[i:], '.')
    ) then
      return jsonb_build_object(
        'error', jsonb_build_object(
          'http_code', 400,
          'message',
          'Temporary or disposable email addresses are not accepted. Please sign up with a permanent work or personal email.'
        )
      );
    end if;
  end loop;

  return '{}'::jsonb;
end;
$$;


-- ── 4. Permissions ──────────────────────────────────────────────────────────
-- The auth service runs the hook as supabase_auth_admin.
grant usage  on schema public to supabase_auth_admin;
grant execute on function public.block_disposable_email(jsonb) to supabase_auth_admin;
grant select  on table public.disposable_domains to supabase_auth_admin;

-- Keep everyone else out of the function.
revoke execute on function public.block_disposable_email(jsonb) from authenticated, anon, public;
