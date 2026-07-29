import React from "react";
import ReactDOM from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import { App, ErrorPage } from "./App";
import {
  Backups,
  Dashboard,
  HealthPage,
  Logs,
  ProxyHosts,
  ResourcePage,
  Revisions,
  Settings,
  Setup,
  actionFor,
  dashboardLoader,
  healthLoader,
  logsLoader,
  proxyHostAction,
  proxyHostLoader,
  resourceLoader,
  revisionsLoader,
  revisionsAction,
  settingsLoader,
  backupsAction,
} from "./pages";
import { loadSession } from "./api";
import "./styles.css";

const router = createBrowserRouter([
  {
    path: "/",
    element: <App />,
    errorElement: <ErrorPage />,
    loader: () => loadSession(),
    children: [
      { index: true, element: <Dashboard />, loader: dashboardLoader },
      { path: "setup", element: <Setup /> },
      {
        path: "proxy-hosts",
        element: <ProxyHosts />,
        loader: proxyHostLoader,
        action: proxyHostAction,
      },
      ...(["stream-hosts", "certificates", "access-policies", "users"] as const).map(
        (resource) => ({
          path: resource,
          element: <ResourcePage resource={resource} />,
          loader: () => resourceLoader(resource),
          action: actionFor(resource),
        }),
      ),
      { path: "health", element: <HealthPage />, loader: healthLoader },
      { path: "logs", element: <Logs />, loader: logsLoader },
      { path: "revisions", element: <Revisions />, loader: revisionsLoader, action: revisionsAction },
      { path: "backups", element: <Backups />, action: backupsAction },
      { path: "settings", element: <Settings />, loader: settingsLoader },
    ],
  },
]);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>,
);
