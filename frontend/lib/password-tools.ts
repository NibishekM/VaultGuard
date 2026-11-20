export type PasswordCheck = { label: string; ok: boolean }
export type PasswordAnalysis = { score: number; level: "Very Weak" | "Weak" | "Moderate" | "Strong" | "Excellent"; checks: PasswordCheck[]; suggestions: string[]; estimate: string }

export function analyzePassword(value: string): PasswordAnalysis {
  const checks: PasswordCheck[] = [
    { label: "At least 12 characters", ok: value.length >= 12 },
    { label: "Uppercase and lowercase letters", ok: /[a-z]/.test(value) && /[A-Z]/.test(value) },
    { label: "Includes numbers", ok: /\d/.test(value) },
    { label: "Includes symbols", ok: /[^A-Za-z0-9]/.test(value) },
    { label: "Avoids common sequences", ok: Boolean(value) && !/(1234|abcd|qwerty|password|letmein|0000)/i.test(value) },
  ]
  let score = Math.min(42, value.length * 3.2) + checks.slice(1).reduce((sum, item) => sum + (item.ok ? 11 : 0), 0)
  if (/(.)\1{2,}/.test(value)) score -= 12
  if (/^(password|qwerty|letmein|welcome)/i.test(value)) score -= 25
  score = value.length ? Math.max(0, Math.min(100, Math.round(score))) : 0
  const level = score >= 86 ? "Excellent" : score >= 70 ? "Strong" : score >= 48 ? "Moderate" : score >= 25 ? "Weak" : "Very Weak"
  const suggestions = checks.filter(item => !item.ok).map(item => item.label === "Avoids common sequences" ? "Replace predictable sequences with unrelated characters." : `Add ${item.label.toLowerCase()}.`)
  if (/(.)\1{2,}/.test(value)) suggestions.push("Avoid repeating the same character several times.")
  const estimate = score < 25 ? "Very quickly" : score < 48 ? "Hours to days" : score < 70 ? "Months to years" : score < 86 ? "Many years" : "A very long time"
  return { score, level, checks, suggestions: suggestions.length ? suggestions : ["Great work. Keep this password unique to one account."] , estimate }
}

const LOWER = "abcdefghijkmnopqrstuvwxyz"
const UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
const DIGITS = "23456789"
const SYMBOLS = "!@#$%&*+-=?_"
const WORDS = ["amber", "anchor", "apricot", "atlas", "bamboo", "beacon", "birch", "bluebird", "cactus", "canyon", "cedar", "cinder", "clover", "comet", "copper", "coral", "cricket", "dawn", "delta", "drift", "ember", "falcon", "fern", "fjord", "flint", "forest", "frost", "garden", "glacier", "harbor", "hazel", "island", "juniper", "lantern", "lilac", "maple", "marble", "meadow", "meteor", "mosaic", "nectar", "north", "ocean", "olive", "orbit", "otter", "pebble", "pepper", "planet", "plum", "prairie", "quartz", "raven", "river", "robin", "rocket", "saffron", "shadow", "silver", "spruce", "summit", "thistle", "timber", "topaz", "valley", "velvet", "violet", "willow", "window", "winter", "zephyr"]

function randomInt(max: number): number {
  if (!Number.isSafeInteger(max) || max < 1 || max > 0x100000000) throw new Error("Invalid random range")
  const ceiling = Math.floor(0x100000000 / max) * max
  const sample = new Uint32Array(1)
  do { crypto.getRandomValues(sample) } while (sample[0] >= ceiling)
  return sample[0] % max
}
function shuffled<T>(items: T[]): T[] {
  const output = [...items]
  for (let i = output.length - 1; i > 0; i--) { const j = randomInt(i + 1); [output[i], output[j]] = [output[j], output[i]] }
  return output
}
function choose(chars: string): string { return chars[randomInt(chars.length)] }

export function generateRandomPassword(length: number, options: { upper: boolean; lower: boolean; numbers: boolean; symbols: boolean }): string {
  const groups = [options.upper ? UPPER : "", options.lower ? LOWER : "", options.numbers ? DIGITS : "", options.symbols ? SYMBOLS : ""].filter(Boolean)
  if (!groups.length) throw new Error("Choose at least one character type.")
  if (length < groups.length) throw new Error("Choose a longer length to include every selected type.")
  const alphabet = groups.join("")
  const output = groups.map(choose)
  while (output.length < length) output.push(choose(alphabet))
  return shuffled(output).join("")
}

export function generatePassphrase(wordCount: number, separator: string, addNumber: boolean, addSymbol: boolean, inspiration = ""): string {
  const theme = inspiration.toLowerCase()
  const themed = theme.includes("nature") || theme.includes("outdoor") ? WORDS.filter(word => /^(bamboo|birch|cactus|cedar|clover|fern|forest|garden|island|juniper|maple|meadow|ocean|river|spruce|willow|winter)$/.test(word)) : WORDS
  const selected = Array.from({ length: wordCount }, () => WORDS[randomInt(themed.length)]).join(separator)
  return `${selected}${addNumber ? `${separator}${randomInt(90) + 10}` : ""}${addSymbol ? `${separator}${choose("!@#$%&*?")}` : ""}`
}
