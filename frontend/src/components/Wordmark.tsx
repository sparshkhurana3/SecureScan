import wordmarkUrl from "../brand/wordmark.svg";

export function Wordmark({ height = 28 }: { height?: number }) {
  return <img src={wordmarkUrl} alt="SonaComstar" height={height} style={{ height }} />;
}
