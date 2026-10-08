import { apiUrl } from "../api/client";
import { filtersToQuery, type HistoryFilters } from "../api/history";

/**
 * The link of the "Export CSV" button: the findings export with the same filters as the findings tab
 * (the whole filtered result, not just the page on screen). The browser downloads it with the
 * session cookie; the server sets `Content-Disposition: attachment` and escapes formula cells.
 */
export function findingsCsvUrl(filters: HistoryFilters): string {
  return apiUrl("/history/findings.csv", filtersToQuery("findings", filters));
}
