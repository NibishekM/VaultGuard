export type SecurityEvent = {
  title: string
  detail: string
  time: string
  tone: "cyan" | "violet" | "green" | "amber"
}

export const securityEvents: SecurityEvent[] = [
  { title: "Security scan completed", detail: "24 accounts checked", time: "Today, 6:42 PM", tone: "green" },
  { title: "New sign-in detected", detail: "Chrome · San Francisco, CA", time: "Today, 2:18 PM", tone: "cyan" },
  { title: "Password updated", detail: "northstar.app", time: "Yesterday, 9:06 AM", tone: "violet" },
  { title: "Weak password found", detail: "One account needs attention", time: "Nov 14, 11:32 AM", tone: "amber" },
]

export const navigationItems = ["Overview", "Password Analyzer", "Password Generator", "Secure Vault", "Security Assistant", "Settings"] as const
export type NavigationItem = (typeof navigationItems)[number]

export const healthBreakdown = [
  { label: "Strong", count: 16, color: "#45D6A0" },
  { label: "Moderate", count: 5, color: "#9275F5" },
  { label: "Weak", count: 3, color: "#E9AA62" },
]
