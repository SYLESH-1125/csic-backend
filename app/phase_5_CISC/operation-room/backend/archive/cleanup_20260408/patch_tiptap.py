import re

with open('c:/CISC/operation-room/frontend/src/components/tiptap/EvidenceBlockNode.tsx', 'r', encoding='utf-8') as f:
    content = f.read()

match_str = r'(function TimelineEventContent\(\{ data, displayMode \}: \{ data: any; displayMode: string \}\) \{\s*const \{[^}]+\} = data.*?)\s*// If we have multiple events'

replace_str = r'''\g<1>
  const clusters = data.clusters || []
  
  // If we have DBSCAN clusters, render them automatically
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
            actor: Count: ,
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

  // If we have multiple events'''

content = re.sub(match_str, replace_str, content, flags=re.DOTALL)

with open('c:/CISC/operation-room/frontend/src/components/tiptap/EvidenceBlockNode.tsx', 'w', encoding='utf-8') as f:
    f.write(content)
