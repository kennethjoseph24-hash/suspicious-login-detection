const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const TOKEN_KEY = "campusguard_token";

export function saveToken(token) {
  if (token) sessionStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  sessionStorage.removeItem(TOKEN_KEY);
}

async function request(path, options = {}) {
  const token = typeof window !== "undefined" ? sessionStorage.getItem(TOKEN_KEY) : null;
  const res = await fetch(`${API_URL}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const message = data?.detail || `Request failed (${res.status})`;
    const error = new Error(typeof message === "string" ? message : JSON.stringify(message));
    error.status = res.status;
    throw error;
  }
  return data;
}

export const api = {
  register: (payload) =>
    request("/api/auth/register", { method: "POST", body: JSON.stringify(payload) }),
  demoLocations: () => request("/api/demo/locations"),
  demoReset: () => request("/api/demo/reset", { method: "POST" }),
  login: (payload) =>
    request("/api/auth/login", { method: "POST", body: JSON.stringify(payload) }),
  verifyOtp: (payload) =>
    request("/api/auth/verify-otp", { method: "POST", body: JSON.stringify(payload) }),
  dashboardStats: () => request("/api/dashboard/stats"),
  datasetOverview: () => request("/api/dashboard/dataset"),
  riskDistribution: () => request("/api/dashboard/risk-distribution"),
  activity: (days = 14) => request(`/api/dashboard/activity?days=${days}`),
  loginAttempts: (params = {}) => {
    const qs = new URLSearchParams(
      Object.entries(params).filter(([, v]) => v !== "" && v !== undefined && v !== null)
    ).toString();
    return request(`/api/login-attempts${qs ? `?${qs}` : ""}`);
  },
  loginAttempt: (id) => request(`/api/login-attempts/${id}`),
  alerts: (params = {}) => {
    const qs = new URLSearchParams(
      Object.entries(params).filter(([, v]) => v !== "" && v !== undefined && v !== null)
    ).toString();
    return request(`/api/alerts${qs ? `?${qs}` : ""}`);
  },
  resolveAlert: (id) => request(`/api/alerts/${id}/resolve`, { method: "POST" }),
};
