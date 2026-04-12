const fs = require('fs');

const path = 'C:/CISC/operation-room/frontend/src/components/studio-v4/dialogs/ExportGateDialog.tsx';
let fileContent = fs.readFileSync(path, 'utf8');

const targetBlock = `                  </div>
                </div>
              </>
            ) : null}`;

const replacementBlock = `                  </div>
                </div>

                {/* Engine selection (for PDF only) */}
                {format === 'pdf' && (
                  <div className="space-y-2 border-t pt-3">
                    <Label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                      Rendering Engine
                    </Label>
                    <div className="grid grid-cols-2 gap-2">
                      <button
                        className={cn(
                          "flex flex-col items-start gap-1 p-3 rounded-lg border transition-all text-left",
                          engine === 'current'
                            ? "border-sky-400 bg-sky-50 dark:bg-sky-950/30"
                            : "border-slate-200 hover:border-slate-300 dark:border-slate-800"
                        )}
                        onClick={() => setEngine('current')}
                      >
                        <span className={cn("text-xs font-bold", engine === 'current' ? "text-sky-700 dark:text-sky-300" : "")}>Standard (Snapshot)</span>
                        <span className="text-[10px] text-muted-foreground text-left leading-snug">Uses Playwright for a reliable webpage image-to-PDF export.</span>
                      </button>
                      <button
                        className={cn(
                          "flex flex-col items-start gap-1 p-3 rounded-lg border transition-all text-left",
                          engine === 'dynamite'
                            ? "border-indigo-400 bg-indigo-50 dark:bg-indigo-950/30"
                            : "border-slate-200 hover:border-slate-300 dark:border-slate-800"
                        )}
                        onClick={() => setEngine('dynamite')}
                      >
                        <span className={cn("text-xs font-bold", engine === 'dynamite' ? "text-indigo-700 dark:text-indigo-300" : "")}>Dynamite Engine (JSON)</span>
                        <span className="text-[10px] text-muted-foreground text-left leading-snug">Renders natively via the exact-match headless web adapter.</span>
                      </button>
                    </div>
                  </div>
                )}
              </>
            ) : null}`;

fileContent = fileContent.replace(targetBlock, replacementBlock);
fs.writeFileSync(path, fileContent);
console.log("Patched UI");
