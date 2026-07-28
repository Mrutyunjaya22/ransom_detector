export function reportLovableError(error: Error, context: { boundary: string }) {
  console.error("Lovable error report:", context.boundary, error);
}
