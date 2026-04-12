import re, sys
fpath = r'c:\CISC\operation-room\frontend\src\components\studio-v4\panels\TimelinePanel.tsx'
with open(fpath, 'r', encoding='utf-8') as f:
    text = f.read()

start = text.find('            {/* Events list */}')
end = text.find('          </CollapsibleContent>', start)

if start == -1 or end == -1:
    print("Cannot find boundaries!")
    sys.exit(1)

new_logic = '''            {/* Events list (Clustered) */}
            <div className="space-y-1.5 pb-4">
              {recentEvents
                .slice(0, 15)
                .map((cluster, i) => (
                  <div
                    key={i}
                    className={cn(
                      "flex items-center gap-2 p-2 rounded-md text-xs transition-colors hover:bg-accent/50 border border-transparent",
                      cluster.cluster_id === 'outliers' && "border-red-500/20 bg-red-50/50"
                    )}
                  >
                    <div className={cn(
                      "w-2 h-2 rounded-full flex-shrink-0",
                      cluster.cluster_id === 'outliers' ? SEVERITY_COLORS.HIGH.dot : SEVERITY_COLORS.INFO.dot
                    )} />
                    <span className="w-16 flex-shrink-0 font-geist-mono text-muted-foreground">
                      {cluster.start ? (formatTime(cluster.start).split(',')[1]?.trim() || formatTime(cluster.start)) : 'N/A'}
                    </span>
                    <span className="font-medium truncate flex-1">
                      Cluster {i + 1} ({cluster.event_count || 0} items)
                    </span>
                    {cluster.cluster_id === 'outliers' && (
                      <span className="text-muted-foreground truncate max-w-[80px]">
                        Scattered
                      </span>
                    )}
                  </div>
                ))}
            </div>
'''

text = text[:start] + new_logic + text[end:]

with open(fpath, 'w', encoding='utf-8') as f:
    f.write(text)
print('Patch 4 completed!')
