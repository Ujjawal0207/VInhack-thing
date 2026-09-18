/**
 * Open Source Security Transition Monitor - Main Application
 */

import React, { useEffect, useState } from 'react';
import {
  Shield,
  Github,
  Globe,
  Package,
  Bell,
  AlertCircle,
  CheckCircle2,
  ExternalLink,
  ChevronRight,
  Sparkles,
  Info,
  Cpu,
  Zap,
} from 'lucide-react';
import { Header } from './components/Header.tsx';
import { ProjectRegistrationModal } from './components/ProjectRegistrationModal.tsx';
import { EngagementPanel } from './components/EngagementPanel.tsx';
import { NotificationCard } from './components/NotificationCard.tsx';
import { ScanResultsView } from './components/ScanResultsView.tsx';
import { ClaimVerificationView } from './components/ClaimVerificationView.tsx';
import { V1V2ReliabilityComparisonView } from './components/V1V2ReliabilityComparisonView.tsx';
import { HackathonDemoFlow } from './components/HackathonDemoFlow.tsx';
import { TestSuiteModal } from './components/TestSuiteModal.tsx';
import { ThresholdsModal } from './components/ThresholdsModal.tsx';
import { Project, SecurityAssessmentNotification, TransitionEvent, WebsiteScanResult } from './types/index.ts';

export default function App() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'demo' | 'verification' | 'reliability' | 'scanner' | 'engagement'>('demo');
  const [currentProjectDetails, setCurrentProjectDetails] = useState<{
    project: Project;
    transitionEvents: TransitionEvent[];
    notifications: SecurityAssessmentNotification[];
    scans: WebsiteScanResult[];
  } | null>(null);

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Modals
  const [isRegisterOpen, setIsRegisterOpen] = useState(false);
  const [isTestOpen, setIsTestOpen] = useState(false);
  const [isThresholdsOpen, setIsThresholdsOpen] = useState(false);

  // Load all projects
  const fetchProjects = async (keepSelection = true) => {
    try {
      setRefreshing(true);
      const res = await fetch('/api/projects');
      const data = await res.json();
      if (data.success && Array.isArray(data.projects)) {
        setProjects(data.projects);

        if (!selectedProjectId || !keepSelection) {
          if (data.projects.length > 0) {
            setSelectedProjectId(data.projects[0].id);
          }
        }
      }
    } catch (err: any) {
      setError(err.message || 'Failed to fetch projects');
    } finally {
      setRefreshing(false);
      setLoading(false);
    }
  };

  // Load selected project details
  const fetchSelectedProjectDetails = async (id: string) => {
    try {
      const res = await fetch(`/api/projects/${id}`);
      const data = await res.json();
      if (data.success) {
        setCurrentProjectDetails({
          project: data.project,
          transitionEvents: data.transitionEvents,
          notifications: data.notifications,
          scans: data.scans,
        });
      }
    } catch (err: any) {
      setError(err.message || 'Failed to fetch project details');
    }
  };

  useEffect(() => {
    fetchProjects(false);
  }, []);

  useEffect(() => {
    if (selectedProjectId) {
      fetchSelectedProjectDetails(selectedProjectId);
    }
  }, [selectedProjectId]);

  const handleProjectRegistered = (newProject: Project) => {
    setProjects((prev) => [...prev, newProject]);
    setSelectedProjectId(newProject.id);
  };

  const handleInitiateScanFromNotification = async (notificationId: string) => {
    if (!selectedProjectId) return;
    try {
      const res = await fetch(`/api/projects/${selectedProjectId}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          useMockScanner: false,
          notificationId,
        }),
      });
      const data = await res.json();
      if (data.success) {
        fetchSelectedProjectDetails(selectedProjectId);
      }
    } catch (err) {
      console.error('Scan failed:', err);
    }
  };

  const handleDismissNotification = async (notificationId: string) => {
    if (!selectedProjectId) return;
    try {
      await fetch(`/api/projects/${selectedProjectId}/notifications/${notificationId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'dismissed' }),
      });
      fetchSelectedProjectDetails(selectedProjectId);
    } catch (err) {
      console.error('Dismiss failed:', err);
    }
  };

  const activeProject = currentProjectDetails?.project;
  const activeNotifications = (currentProjectDetails?.notifications || []).filter(
    (n) => n.status !== 'dismissed'
  );

  return (
    <div className="min-h-screen bg-[#f6f8fa] dark:bg-[#0d1117] text-[#1f2328] dark:text-[#c9d1d9] flex flex-col font-sans antialiased transition-colors">
      <Header
        onOpenRegister={() => setIsRegisterOpen(true)}
        onOpenTestSuite={() => setIsTestOpen(true)}
        onRefresh={() => {
          fetchProjects(true);
          if (selectedProjectId) fetchSelectedProjectDetails(selectedProjectId);
        }}
        isRefreshing={refreshing}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-5 space-y-5">
        {/* GitHub Callout: Educational Transition Philosophy */}
        <div className="bg-[#ddf4ff] dark:bg-[#0c2d6b]/25 text-[#1f2328] dark:text-[#c9d1d9] p-4 rounded-md border border-[#54aeff]/40 dark:border-[#1f6feb]/40 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-bold uppercase tracking-wider text-[#0969da] dark:text-[#58a6ff] bg-[#0969da]/10 dark:bg-[#1f6feb]/20 px-2 py-0.5 rounded-full border border-[#0969da]/20 dark:border-[#1f6feb]/30">
                Growth-Moment Advisory
              </span>
              <span className="text-xs text-[#656d76] dark:text-[#8b949e]">
                Hobby-to-Public Open Source Transition
              </span>
            </div>
            <h1 className="text-sm font-semibold text-[#1f2328] dark:text-[#f0f6fc]">
              Open-Source Project Website Security Assessment
            </h1>
            <p className="text-xs text-[#656d76] dark:text-[#8b949e] max-w-3xl leading-relaxed">
              When hobby tools reach 1,000 GitHub stars or 10,000 npm downloads, visitor volume surges. This monitor detects growth milestone crossings and provides educational, non-invasive website security assessments—strictly evaluating web transport and headers, never the source code or repository.
            </p>
          </div>

          <div className="flex items-center gap-2 self-start md:self-center shrink-0">
            <button
              onClick={() => setIsTestOpen(true)}
              className="px-3 py-1.5 text-xs font-medium text-[#24292f] dark:text-[#c9d1d9] bg-white dark:bg-[#21262d] hover:bg-[#f6f8fa] dark:hover:bg-[#30363d] rounded-md border border-[#d0d7de] dark:border-[#30363d] shadow-2xs flex items-center gap-1.5 transition-colors"
            >
              <Shield className="w-3.5 h-3.5 text-[#0969da] dark:text-[#58a6ff]" />
              <span>Verify Pipeline</span>
            </button>
          </div>
        </div>

        {error && (
          <div className="p-3 bg-[#ffebe9] dark:bg-[#490202]/30 border border-[#ff8182]/40 dark:border-[#f85149]/40 rounded-md text-xs text-[#cf222e] dark:text-[#ff7b72] flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* GitHub Style Pinned Repositories / Project Selector */}
        <div className="space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#1f2328] dark:text-[#f0f6fc] flex items-center gap-1.5">
              <span>Monitored Repositories</span>
              <span className="px-1.5 py-0.2 rounded-full text-[10px] font-semibold bg-[#afb8c1]/20 dark:bg-[#30363d] text-[#656d76] dark:text-[#8b949e]">
                {projects.length}
              </span>
            </span>
            <span className="text-[11px] text-[#656d76] dark:text-[#8b949e]">
              Select a repository to inspect engagement indicators, milestone alerts, and security scans
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {projects.map((proj) => {
              const isSelected = proj.id === selectedProjectId;
              const hasMilestone =
                (proj.currentMetrics?.githubStars || 0) >= proj.thresholds.githubStars ||
                (proj.currentMetrics?.npmDownloads || 0) >= proj.thresholds.npmDownloads;

              return (
                <div
                  key={proj.id}
                  onClick={() => setSelectedProjectId(proj.id)}
                  className={`p-3.5 rounded-md border transition-all cursor-pointer flex flex-col justify-between gap-3 ${
                    isSelected
                      ? 'bg-white dark:bg-[#161b22] border-[#0969da] dark:border-[#58a6ff] ring-1 ring-[#0969da] dark:ring-[#58a6ff] shadow-xs'
                      : 'bg-white dark:bg-[#161b22] border-[#d0d7de] dark:border-[#30363d] hover:border-[#8c959f] dark:hover:border-[#8b949e]'
                  }`}
                >
                  <div>
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-1.5 min-w-0">
                        <Github className="w-3.5 h-3.5 text-[#656d76] dark:text-[#8b949e] shrink-0" />
                        <h3 className="text-xs font-semibold text-[#0969da] dark:text-[#58a6ff] hover:underline truncate">
                          {proj.name}
                        </h3>
                      </div>
                      {hasMilestone && (
                        <span className="text-[10px] font-semibold text-[#9a6700] dark:text-[#eac54f] bg-[#fff8c5] dark:bg-[#633c01]/30 border border-[#d4a72c]/40 dark:border-[#d29922]/40 px-1.5 py-0.5 rounded-full shrink-0 flex items-center gap-1">
                          <Sparkles className="w-3 h-3 text-[#bf8700] dark:text-[#d29922]" /> Milestone
                        </span>
                      )}
                    </div>
                    <div className="text-[11px] text-[#656d76] dark:text-[#8b949e] flex items-center gap-1 font-mono mt-1.5 truncate">
                      <Globe className="w-3 h-3 shrink-0 text-[#656d76] dark:text-[#8b949e]" />
                      <span className="truncate">{proj.websiteUrl}</span>
                    </div>
                  </div>

                  <div className="flex items-center justify-between text-[11px] text-[#656d76] dark:text-[#8b949e] border-t border-[#d0d7de]/60 dark:border-[#30363d] pt-2">
                    <span className="flex items-center gap-1">
                      <span className="w-2 h-2 rounded-full bg-[#f1e05a]" /> {/* JS / Yellow dot */}
                      <span>
                        {proj.currentMetrics?.githubStars !== null && proj.currentMetrics?.githubStars !== undefined
                          ? `★ ${proj.currentMetrics.githubStars.toLocaleString()}`
                          : '★ —'}
                      </span>
                    </span>
                    <span className="flex items-center gap-0.5 font-medium text-[#0969da] dark:text-[#58a6ff]">
                      <span>Inspect</span>
                      <ChevronRight className="w-3 h-3" />
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Selected Project Main View */}
        {activeProject && currentProjectDetails && (
          <div className="space-y-5">
            {/* GitHub Box: Project Overview Card */}
            <div className="bg-white dark:bg-[#161b22] rounded-md border border-[#d0d7de] dark:border-[#30363d] overflow-hidden shadow-2xs">
              <div className="bg-[#f6f8fa] dark:bg-[#161b22] px-4 py-3 border-b border-[#d0d7de] dark:border-[#30363d] flex flex-col md:flex-row md:items-center justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <Github className="w-4 h-4 text-[#656d76] dark:text-[#8b949e]" />
                    <h2 className="text-sm font-bold text-[#1f2328] dark:text-[#f0f6fc]">
                      {activeProject.name}
                    </h2>
                    <span className="px-1.5 py-0.2 rounded-full text-[10px] font-medium border border-[#d0d7de] dark:border-[#30363d] text-[#656d76] dark:text-[#8b949e] bg-white dark:bg-[#21262d]">
                      Public Target
                    </span>
                  </div>
                  <div className="flex flex-wrap items-center gap-3 text-xs text-[#656d76] dark:text-[#8b949e] mt-1">
                    <a
                      href={activeProject.githubRepoUrl}
                      target="_blank"
                      rel="noreferrer"
                      className="flex items-center gap-1 text-[#0969da] dark:text-[#58a6ff] hover:underline font-mono"
                    >
                      <span>{activeProject.githubOwner}/{activeProject.githubRepo}</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                    <span>•</span>
                    <a
                      href={activeProject.websiteUrl}
                      target="_blank"
                      rel="noreferrer"
                      className="flex items-center gap-1 text-[#0969da] dark:text-[#58a6ff] hover:underline font-mono"
                    >
                      <Globe className="w-3 h-3" />
                      <span>{activeProject.websiteUrl}</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                    {activeProject.npmPackageName && (
                      <>
                        <span>•</span>
                        <span className="flex items-center gap-1 font-mono text-[#656d76] dark:text-[#8b949e]">
                          <Package className="w-3 h-3" />
                          <span>{activeProject.npmPackageName}</span>
                        </span>
                      </>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-2 self-start md:self-center">
                  <div className="text-right text-xs">
                    <span className="text-[#656d76] dark:text-[#8b949e] block text-[10px] uppercase font-semibold">
                      Milestone Targets
                    </span>
                    <span className="text-[#1f2328] dark:text-[#c9d1d9] font-medium">
                      ★ {activeProject.thresholds.githubStars.toLocaleString()} • ⤓ {activeProject.thresholds.npmDownloads.toLocaleString()}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* GitHub Style Advisory Notification */}
            {activeNotifications.length > 0 && (
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <Bell className="w-4 h-4 text-[#0969da] dark:text-[#58a6ff]" />
                  <h3 className="text-xs font-bold uppercase tracking-wider text-[#656d76] dark:text-[#8b949e]">
                    Security Assessment Guidance ({activeNotifications.length})
                  </h3>
                </div>
                {activeNotifications.map((notif) => (
                  <NotificationCard
                    key={notif.id}
                    notification={notif}
                    onInitiateScan={handleInitiateScanFromNotification}
                    onDismiss={handleDismissNotification}
                  />
                ))}
              </div>
            )}

            {/* GitHub Style Sub-navigation Tabs */}
            <div className="border-b border-[#d0d7de] dark:border-[#30363d] flex items-center gap-1 overflow-x-auto text-xs">
              <button
                onClick={() => setActiveTab('demo')}
                className={`px-3.5 py-2 font-medium border-b-2 flex items-center gap-2 transition-colors whitespace-nowrap ${
                  activeTab === 'demo'
                    ? 'border-[#0969da] dark:border-[#58a6ff] text-[#0969da] dark:text-[#58a6ff] font-bold bg-[#0969da]/5'
                    : 'border-transparent text-[#656d76] dark:text-[#8b949e] hover:text-[#1f2328] dark:hover:text-[#f0f6fc]'
                }`}
                id="tab-hackathon-demo"
              >
                <Zap className="w-4 h-4 text-amber-500" />
                <span>3-Min Hackathon Demo</span>
                <span className="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-amber-500/15 text-amber-700 dark:text-amber-400 border border-amber-500/30">
                  Walkthrough
                </span>
              </button>

              <button
                onClick={() => setActiveTab('verification')}
                className={`px-3.5 py-2 font-medium border-b-2 flex items-center gap-2 transition-colors whitespace-nowrap ${
                  activeTab === 'verification'
                    ? 'border-[#fd8c73] dark:border-[#f78166] text-[#1f2328] dark:text-[#f0f6fc] font-semibold'
                    : 'border-transparent text-[#656d76] dark:text-[#8b949e] hover:text-[#1f2328] dark:hover:text-[#f0f6fc]'
                }`}
              >
                <Shield className="w-4 h-4 text-[#0969da] dark:text-[#58a6ff]" />
                <span>Evidence & Claim Verification</span>
                <span className="px-1.5 py-0.2 rounded-full text-[10px] font-semibold bg-[#0969da]/10 dark:bg-[#1f6feb]/20 text-[#0969da] dark:text-[#58a6ff]">
                  3 States
                </span>
              </button>

              <button
                onClick={() => setActiveTab('reliability')}
                className={`px-3.5 py-2 font-medium border-b-2 flex items-center gap-2 transition-colors whitespace-nowrap ${
                  activeTab === 'reliability'
                    ? 'border-[#fd8c73] dark:border-[#f78166] text-[#1f2328] dark:text-[#f0f6fc] font-semibold'
                    : 'border-transparent text-[#656d76] dark:text-[#8b949e] hover:text-[#1f2328] dark:hover:text-[#f0f6fc]'
                }`}
                id="tab-v1-v2-reliability"
              >
                <Cpu className="w-4 h-4 text-indigo-500" />
                <span>V1 vs V2 Reliability Benchmark</span>
                <span className="px-1.5 py-0.2 rounded-full text-[10px] font-semibold bg-indigo-500/10 dark:bg-indigo-500/20 text-indigo-600 dark:text-indigo-400">
                  V1 / V2
                </span>
              </button>

              <button
                onClick={() => setActiveTab('scanner')}
                className={`px-3.5 py-2 font-medium border-b-2 flex items-center gap-2 transition-colors whitespace-nowrap ${
                  activeTab === 'scanner'
                    ? 'border-[#fd8c73] dark:border-[#f78166] text-[#1f2328] dark:text-[#f0f6fc] font-semibold'
                    : 'border-transparent text-[#656d76] dark:text-[#8b949e] hover:text-[#1f2328] dark:hover:text-[#f0f6fc]'
                }`}
              >
                <Globe className="w-4 h-4 text-[#656d76] dark:text-[#8b949e]" />
                <span>Website Security Scanner</span>
                <span className="px-1.5 py-0.2 rounded-full text-[10px] font-semibold bg-[#afb8c1]/20 dark:bg-[#30363d] text-[#656d76] dark:text-[#8b949e]">
                  {currentProjectDetails.scans.length}
                </span>
              </button>

              <button
                onClick={() => setActiveTab('engagement')}
                className={`px-3.5 py-2 font-medium border-b-2 flex items-center gap-2 transition-colors whitespace-nowrap ${
                  activeTab === 'engagement'
                    ? 'border-[#fd8c73] dark:border-[#f78166] text-[#1f2328] dark:text-[#f0f6fc] font-semibold'
                    : 'border-transparent text-[#656d76] dark:text-[#8b949e] hover:text-[#1f2328] dark:hover:text-[#f0f6fc]'
                }`}
              >
                <Sparkles className="w-4 h-4 text-[#bf8700] dark:text-[#d29922]" />
                <span>Growth Milestones & Engagement</span>
                <span className="px-1.5 py-0.2 rounded-full text-[10px] font-semibold bg-[#afb8c1]/20 dark:bg-[#30363d] text-[#656d76] dark:text-[#8b949e]">
                  {currentProjectDetails.transitionEvents.length}
                </span>
              </button>
            </div>

            {/* Tab Views */}
            {activeTab === 'demo' && (
              <HackathonDemoFlow />
            )}

            {activeTab === 'verification' && (
              <ClaimVerificationView projectId={activeProject.id} />
            )}

            {activeTab === 'reliability' && (
              <V1V2ReliabilityComparisonView />
            )}

            {activeTab === 'scanner' && (
              <ScanResultsView
                project={activeProject}
                scans={currentProjectDetails.scans}
                onScanInitiated={() => {
                  fetchSelectedProjectDetails(activeProject.id);
                  fetchProjects(true);
                }}
              />
            )}

            {activeTab === 'engagement' && (
              <EngagementPanel
                project={activeProject}
                events={currentProjectDetails.transitionEvents}
                onMetricsUpdated={() => {
                  fetchSelectedProjectDetails(activeProject.id);
                  fetchProjects(true);
                }}
                onOpenThresholds={() => setIsThresholdsOpen(true)}
              />
            )}
          </div>
        )}
      </main>

      {/* Modals */}
      <ProjectRegistrationModal
        isOpen={isRegisterOpen}
        onClose={() => setIsRegisterOpen(false)}
        onRegistered={handleProjectRegistered}
      />

      {activeProject && (
        <ThresholdsModal
          isOpen={isThresholdsOpen}
          onClose={() => setIsThresholdsOpen(false)}
          project={activeProject}
          onSaved={(newThresholds) => {
            fetchSelectedProjectDetails(activeProject.id);
            fetchProjects(true);
          }}
        />
      )}

      <TestSuiteModal isOpen={isTestOpen} onClose={() => setIsTestOpen(false)} />

      {/* GitHub Style Clean Footer */}
      <footer className="mt-12 border-t border-[#d0d7de] dark:border-[#30363d] bg-white dark:bg-[#161b22] py-5 text-xs text-[#656d76] dark:text-[#8b949e] transition-colors">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Github className="w-4 h-4 text-[#656d76] dark:text-[#8b949e]" />
            <span>
              <strong className="text-[#1f2328] dark:text-[#f0f6fc]">Open Source Security Transition Monitor</strong> — Educational website security assessment at open-source growth milestones.
            </span>
          </div>
          <div className="flex items-center gap-3 text-[11px] text-[#656d76] dark:text-[#8b949e]">
            <span>Deterministic Engine</span>
            <span>•</span>
            <span>No Codebase Scanning</span>
            <span>•</span>
            <span>Opt-in Assessment</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
