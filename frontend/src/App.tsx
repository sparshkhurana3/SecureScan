import { Wordmark } from "./components/Wordmark";

export function App() {
  return (
    <main style={{ display: "grid", placeItems: "center", minHeight: "100vh", gap: 16 }}>
      <div style={{ textAlign: "center" }}>
        <Wordmark height={36} />
        <h1 style={{ fontSize: 20, fontWeight: 600, margin: "16px 0 0" }}>SecureScan</h1>
      </div>
    </main>
  );
}
