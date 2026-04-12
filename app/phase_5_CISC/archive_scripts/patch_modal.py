import re
f = r'c:\CISC\operation-room\frontend\src\components\studio-v4\dialogs\ExportPreviewModal.tsx'
with open(f, 'r', encoding='utf-8') as file:
    txt = file.read()

pattern = r'<DialogFooter>.*?</DialogFooter>'
new_footer = '''<DialogFooter className="flex sm:flex-row flex-col justify-between gap-2 mt-4">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          {focusMode !== 'Evidence' && (
            <div className="flex sm:flex-row flex-col gap-2">
              <Button
                variant="outline"
                className="border-sky-600 text-sky-600 hover:bg-sky-50 whitespace-nowrap"
                onClick={() => {
                  onOpenChange(false);
                  onConfirm('standard');
                }}
              >
                Standard Export
              </Button>
              <Button
                className="bg-[rgb(3,7,18)] hover:bg-[rgb(3,7,18)]/90 text-white whitespace-nowrap"
                onClick={() => {
                  onOpenChange(false);
                  onConfirm('dynamite');
                }}
              >
                Formal Dynamite Report
              </Button>
            </div>
          )}
        </DialogFooter>'''

txt = re.sub(pattern, new_footer, txt, flags=re.DOTALL)
with open(f, 'w', encoding='utf-8') as file:
    file.write(txt)
