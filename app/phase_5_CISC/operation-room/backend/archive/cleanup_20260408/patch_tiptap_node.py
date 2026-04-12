import re
with open('c:/CISC/operation-room/frontend/src/components/tiptap/EvidenceBlockNode.tsx', 'r', encoding='utf-8') as f:
    c = f.read()

matchStr = r'(function TimelineEventContent\(\{ data, displayMode \}: \{ data: any; displayMode: string \}\) \{\s*const \{[^}]+\} = data.*?)(\s*// If we have multiple events)'
repStr = r'''\g<1>
  const clusters = data.clusters || []
  
  if (clusters && clusters.length > 0) {
    return (
      <div className="p-4">
        <TimelineVerticalChart
          events={clusters.map((c: any) => ({
            id: String(c.cluster_id || Math.random()),
            timestamp: c.start || "N/A",
            event_type: "Density Cluster",
            severity: c.cluster_id === 'outliers' ? 'high' : 'info',
            source: "DBSCAN",
            actor: `Count: ${c.event_count || 0}`,
          }))}
          highlightAnchor={true}
          className={displayMode === 'compact' ? 'max-h-48' : 'max-h-80'}
        />
        {displayMode === 'compact' && clusters.length > 5 && (
          <p className="text-xs text-muted-foreground text-center mt-2">
            + {clusters.length - 5} more clusters
          </p>
        )}
      </div>
    )
  }
\g<2>'''

c = re.sub(matchStr, repStr, c, flags=re.DOTALL)
with open('c:/CISC/operation-room/frontend/src/components/tiptap/EvidenceBlockNode.tsx', 'w', encoding='utf-8') as f:
    f.write(c)
