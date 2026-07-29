import { useEffect, useRef } from "react";
import {
  isRouteErrorResponse,
  NavLink,
  Outlet,
  useLoaderData,
  useLocation,
  useNavigation,
  useRouteError,
} from "react-router-dom";
import { logout, permits, type Action, type Session } from "./api";

const navigation: Array<[string, string, Action]> = [
  ["/", "Dashboard", "read_status"],
  ["/proxy-hosts", "Proxy Hosts", "read_proxy_hosts"],
  ["/stream-hosts", "Stream Hosts", "read_stream_hosts"],
  ["/certificates", "Certificates", "read_certificate_objects"],
  ["/access-policies", "Access Policies", "read_access_policies"],
  ["/users", "Users", "read_users"],
  ["/health", "Health", "read_status"],
  ["/logs", "Logs", "read_audit"],
  ["/revisions", "Revisions", "read_revisions"],
  ["/backups", "Backups", "create_backup"],
  ["/settings", "Settings", "read_status"],
];

export function App() {
  const session = useLoaderData() as Session;
  const location = useLocation();
  const navigationState = useNavigation();
  const main = useRef<HTMLElement>(null);

  useEffect(() => {
    main.current?.focus();
  }, [location.pathname]);

  return (
    <div className="app">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header>
        <div>
          <span className="eyebrow">AEGIS CONTROL PLANE</span>
          <h1>AegisProxy</h1>
        </div>
        <div className="identity">
          <span>{session.identity_id}</span>
          <span className={`role role-${session.role}`}>{session.role}</span>
          <button type="button" className="quiet" onClick={() => void logout()}>
            Sign out
          </button>
        </div>
      </header>
      <div className="layout">
        <nav aria-label="Primary">
          {session.owner_id === null && (
            <NavLink to="/setup">First-run setup</NavLink>
          )}
          {navigation
            .filter(([, , action]) => permits(session, action))
            .map(([to, label]) => (
              <NavLink key={to} to={to} end={to === "/"}>
                {label}
              </NavLink>
            ))}
        </nav>
        <main id="main" ref={main} tabIndex={-1} aria-busy={navigationState.state !== "idle"}>
          {navigationState.state !== "idle" && <div className="progress">Updating…</div>}
          <Outlet context={session} />
        </main>
      </div>
    </div>
  );
}

export function ErrorPage() {
  const error = useRouteError();
  const status = isRouteErrorResponse(error)
    ? error.status
    : error instanceof Error
      ? error.message
      : "Unknown error";
  return (
    <main className="error-page">
      <p className="eyebrow">REQUEST STOPPED</p>
      <h1>That action could not be completed</h1>
      <p role="alert">{String(status).slice(0, 240)}</p>
      <a href="/">Return to dashboard</a>
    </main>
  );
}
