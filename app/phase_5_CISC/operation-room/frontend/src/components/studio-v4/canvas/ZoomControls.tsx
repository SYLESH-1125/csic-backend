import React from 'react'
import { Button } from '@/components/ui/button'
import { useStudioStore } from '../store/useStudioStore'
import { cn } from '@/lib/utils'

export const ZoomControls = ({ className }: { className?: string }) => {
  const { zoom, zoomIn, zoomOut } = useStudioStore()
  
  return (
    <div className={cn("flex items-center gap-2", className)}>
      <Button
        variant="ghost"
        size="icon"
        className="h-7 w-7"
        onClick={zoomOut}
        disabled={zoom <= 50}
      >
        <span className="text-lg leading-none">−</span>
      </Button>
      <span className="w-12 text-center font-geist-mono text-xs font-medium">
        {zoom}%
      </span>
      <Button
        variant="ghost"
        size="icon"
        className="h-7 w-7"
        onClick={zoomIn}
        disabled={zoom >= 200}
      >
        <span className="text-lg leading-none">+</span>
      </Button>
    </div>
  )
}
