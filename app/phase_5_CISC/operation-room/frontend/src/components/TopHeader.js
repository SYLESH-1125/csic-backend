'use client';
import { usePathname } from 'next/navigation';
import { LogOut, ShieldCheck, UserRound } from 'lucide-react';

const PAGE_TITLES = {
  '/': { title: 'Main Dashboard', subtitle: 'National Forensic Log Intelligence Platform' },
  '/cases/new': { title: 'Create New Case', subtitle: 'Case Initialization & Evidence Preservation' },
};

function getPageInfo(pathname) {
  if (PAGE_TITLES[pathname]) return PAGE_TITLES[pathname];
  if (pathname.includes('/timeline'))    return { title: 'Timeline Reconstruction', subtitle: 'Unified Event Timeline Analysis' };
  if (pathname.includes('/anomalies'))   return { title: 'Anomaly Detection', subtitle: 'Explainable AI · IF, LOF, Ensemble, DistilBERT' };
  if (pathname.includes('/correlation')) return { title: 'Correlation & Root-Cause', subtitle: 'Entity Graph · MITRE ATT&CK Mapping' };
  if (pathname.includes('/crud'))        return { title: 'CRUD & Data-Access', subtitle: 'Operation Classification & Sensitivity Analysis' };
  if (pathname.includes('/exfiltration')) return { title: 'Data Exfiltration Intelligence', subtitle: '9-Engine Pipeline · Behaviour Graphs · Intent-Aware Detection' };
  if (pathname.includes('/network'))     return { title: 'Network & Exfiltration', subtitle: 'Flow Analysis · Threat Intelligence · Exfil Detection' };
  if (pathname.includes('/depth'))       return { title: 'Depth & Impact', subtitle: '4D Penetration Assessment · Business Impact' };
  if (pathname.includes('/studio-v4'))   return { title: 'Report Studio V4', subtitle: 'Canva-style Forensic Workspace · Evidence-Bound Editing' };
  if (pathname.includes('/cases/'))      return { title: 'Case Dashboard', subtitle: 'Evidence & Chain-of-Custody Management' };
  return { title: 'NFLIP', subtitle: 'National Forensic Log Intelligence Platform' };
}

export default function TopHeader() {
  const pathname = usePathname();
  const { title, subtitle } = getPageInfo(pathname);

  return (
    <div className="top-header">
      <div>
        <div className="top-header-title">{title}</div>
        <div className="top-header-subtitle">{subtitle}</div>
      </div>
      <div className="top-header-right">
        <span className="session-badge">
          <ShieldCheck size={13} />
          Session Active
        </span>
        <span className="header-user-pill">
          <UserRound size={13} />
          Investigator
        </span>
        <button className="btn btn-ghost btn-sm">
          <LogOut size={13} />
          Logout
        </button>
      </div>
    </div>
  );
}
