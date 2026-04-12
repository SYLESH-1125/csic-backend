"use client"

import { TooltipProvider } from "@/components/ui/tooltip";

export default function StudioLayout({ children }) {
	return (
		<TooltipProvider>{children}</TooltipProvider>
	);
}