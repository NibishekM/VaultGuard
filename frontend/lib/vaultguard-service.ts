export type VaultCategory = "Personal" | "Work" | "Finance" | "Social"
export type VaultHealth = "Strong" | "Moderate" | "Weak"
export type VaultEntry = { id: string; service: string; username: string; category: VaultCategory; health: VaultHealth; favorite: boolean; notes: string; demoSecret: string }

export const demoVaultEntries: VaultEntry[] = [
  { id: "v-01", service: "Northstar Mail", username: "alex.morgan@example.test", category: "Personal", health: "Strong", favorite: true, notes: "Personal email · demo record", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
  { id: "v-02", service: "Atlas Finance", username: "alex.morgan@example.test", category: "Finance", health: "Strong", favorite: true, notes: "Sample financial account", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
  { id: "v-03", service: "Brightside Studio", username: "alex@brightside.example", category: "Work", health: "Moderate", favorite: false, notes: "Work workspace · demo record", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
  { id: "v-04", service: "Frame Social", username: "alex.morgan", category: "Social", health: "Weak", favorite: false, notes: "Sample social account", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
  { id: "v-05", service: "Cedar Cloud", username: "alex.morgan@example.test", category: "Work", health: "Strong", favorite: false, notes: "Sample storage account", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
  { id: "v-06", service: "Wavelength Music", username: "alex.morgan", category: "Personal", health: "Weak", favorite: true, notes: "Sample subscription", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
  { id: "v-07", service: "Pinecone Community", username: "alex.morgan", category: "Social", health: "Moderate", favorite: false, notes: "Sample community login", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
  { id: "v-08", service: "Harbor Credit", username: "alex.morgan@example.test", category: "Finance", health: "Strong", favorite: false, notes: "Sample financial account", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
  { id: "v-09", service: "Canopy Storage", username: "alex.morgan@example.test", category: "Personal", health: "Strong", favorite: false, notes: "Sample file storage", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
  { id: "v-10", service: "Morrow Calendar", username: "alex.morgan@example.test", category: "Work", health: "Strong", favorite: false, notes: "Sample work calendar", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
  { id: "v-11", service: "OpenTrail Forum", username: "alex.morgan", category: "Social", health: "Moderate", favorite: false, notes: "Sample community account", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
  { id: "v-12", service: "Pocket Lantern", username: "alex.morgan@example.test", category: "Personal", health: "Strong", favorite: false, notes: "Sample reading list", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
  { id: "v-13", service: "Copperline Payments", username: "alex.morgan@example.test", category: "Finance", health: "Strong", favorite: false, notes: "Sample payments account", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
  { id: "v-14", service: "Monogram Studio", username: "alex@brightside.example", category: "Work", health: "Strong", favorite: false, notes: "Sample design workspace", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
  { id: "v-15", service: "Daybreak Journal", username: "alex.morgan@example.test", category: "Personal", health: "Moderate", favorite: false, notes: "Sample journal account", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
  { id: "v-16", service: "Marble Analytics", username: "alex@brightside.example", category: "Work", health: "Strong", favorite: false, notes: "Sample analytics tool", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
  { id: "v-17", service: "Finch Travel", username: "alex.morgan@example.test", category: "Personal", health: "Strong", favorite: false, notes: "Sample travel profile", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
  { id: "v-18", service: "CommonGround", username: "alex.morgan", category: "Social", health: "Strong", favorite: false, notes: "Sample social profile", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
  { id: "v-19", service: "Atlas Investing", username: "alex.morgan@example.test", category: "Finance", health: "Strong", favorite: false, notes: "Sample investing account", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
  { id: "v-20", service: "Fieldnote Docs", username: "alex@brightside.example", category: "Work", health: "Moderate", favorite: false, notes: "Sample document workspace", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
  { id: "v-21", service: "Rook & Pine", username: "alex.morgan@example.test", category: "Personal", health: "Strong", favorite: false, notes: "Sample shopping account", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
  { id: "v-22", service: "Sidecar Network", username: "alex.morgan", category: "Social", health: "Strong", favorite: false, notes: "Sample professional profile", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
  { id: "v-23", service: "Kindred Rewards", username: "alex.morgan@example.test", category: "Finance", health: "Weak", favorite: false, notes: "Sample rewards account · review recommended", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
  { id: "v-24", service: "Lighthouse Notes", username: "alex.morgan@example.test", category: "Personal", health: "Strong", favorite: false, notes: "Sample notes account", demoSecret: "DEMO-ONLY · NOT A REAL PASSWORD" },
]

export const assistantAnswers: Record<string, string> = {
  "How can I improve my security score?": "Start with the three weak passwords shown in your demo overview. Replace each with a unique, generated passphrase and enable multi-factor authentication wherever it is available.",
  "Which passwords should I update first?": "Prioritize accounts that protect other accounts: your email, financial services, and any account with a weak or reused password. The vault records here are fictional demo data.",
  "How do I create a strong passphrase?": "Choose four or more unrelated words, use a separator, and avoid quotes or personal details. VaultGuard’s demo generator can create a random example locally in your browser.",
  "What is multi-factor authentication?": "Multi-factor authentication adds a second proof of identity, such as an authenticator-app code or security key. It helps protect an account even if a password is exposed.",
}

export interface VaultGuardService {
  listVaultEntries(): VaultEntry[]
  getAssistantResponse(prompt: string): string
}

export const localDemoService: VaultGuardService = {
  listVaultEntries: () => demoVaultEntries.map(entry => ({ ...entry })),
  getAssistantResponse: (prompt: string) => assistantAnswers[prompt] ?? "For this frontend demo, I can offer general security guidance. Use unique passwords, turn on multi-factor authentication, and keep recovery options up to date. No password or vault data is sent to an AI service.",
}
