import sys

with open(sys.argv[1], 'r', encoding='utf-8') as f:
    text = f.read()

old_search_params = '''  searchParams: { docId: string }
}) {
  const caseId = params.id
  const docId = searchParams.docId'''

new_search_params = '''  searchParams: { docId: string, coverId?: string }
}) {
  const caseId = params.id
  const docId = searchParams.docId
  const coverId = searchParams.coverId'''

old_render = '''      {/* Render core pages exactly as DocumentCanvas does */}
      <div className="flex flex-col items-center">
        {pages.map((page, i) => ('''


new_render = '''      {/* Render Cover Page if selected */}
      <div className="flex flex-col items-center">
        {coverId && (
          <div
            className="relative bg-white page-break-after overflow-hidden print-page shadow-none border-none"
            style={{ width: A4_WIDTH, height: A4_HEIGHT, pageBreakAfter: 'always' }}
          >
            <div 
              style={{
                position: 'absolute', inset: 0,
                backgroundImage: 'url("/templates/' + coverId + '/cover_' + coverId.replace('template_','') + '.png")',
                backgroundSize: 'cover', backgroundPosition: 'center',
                printColorAdjust: 'exact', WebkitPrintColorAdjust: 'exact'
              }}
            />
          </div>
        )}

      {/* Render core pages exactly as DocumentCanvas does */}
        {pages.map((page, i) => ('''

if old_search_params in text:
    text = text.replace(old_search_params, new_search_params)
if old_render in text:
    text = text.replace(old_render, new_render)

with open(sys.argv[1], 'w', encoding='utf-8') as f:
    f.write(text)
print("Updated print page")
