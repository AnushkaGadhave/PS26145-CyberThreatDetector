import React from 'react';
import { ArrowUpRight } from 'lucide-react';


interface FooterProps {
  onNavigate: (route: string) => void;
}

export const Footer: React.FC<FooterProps> = ({ onNavigate }) => {
  const links = [
    { name: 'Product', href: '#product' },
    { name: 'How It Works', href: '#how-it-works' },
    { name: 'Threat Detection', href: '#threat-detection' },
    { name: 'Architecture', href: '#architecture' },
    { name: 'Reports', href: '#explainable' },
  ];

  const handleLinkClick = (e: React.MouseEvent<HTMLAnchorElement>, href: string) => {
    e.preventDefault();
    const el = document.querySelector(href);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <footer className="bg-[#05051F] border-t border-[#242452] py-14 sm:py-18 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-8 pb-12 border-b border-[#242452]/80">
          {/* Brand & Tagline */}
          <div className="space-y-2">
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 rounded-lg bg-[#10103D] border border-[#242452] flex items-center justify-center">
                <span className="w-2 h-2 rounded-full bg-[#A8F500]" />
              </div>
              <span className="font-heading font-extrabold text-xl text-[#F5F5F7] tracking-tight">
                NETRA
              </span>
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-[#10103D] border border-[#242452] text-[#A8F500]">
                SIH PS 26145
              </span>
            </div>
            <p className="text-xs sm:text-sm text-[#A5A5BE] font-sans">
              Passive Network Threat Monitoring • AI-Based Detection in Unidirectional IP Traffic
            </p>
          </div>

          {/* Quick Nav Links */}
          <div className="flex flex-wrap items-center gap-x-6 gap-y-3 text-xs sm:text-sm font-medium text-[#A5A5BE]">
            {links.map((link) => (
              <a
                key={link.name}
                href={link.href}
                onClick={(e) => handleLinkClick(e, link.href)}
                className="hover:text-[#F5F5F7] transition-colors"
              >
                {link.name}
              </a>
            ))}
            <button
              onClick={() => onNavigate('/dashboard')}
              className="text-[#A8F500] hover:text-[#B7FF19] font-semibold transition-colors flex items-center gap-1"
            >
              <span>Dashboard</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Bottom Metadata & Legal */}
        <div className="pt-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs font-mono text-[#A5A5BE]/60">
          <div>
            Smart India Hackathon • Problem Statement 26145 • Technical Prototype
          </div>
          <div className="flex items-center gap-4">
            <span>Read-Only Passive Telemetry</span>
            <span>•</span>
            <span>Zero Payload Inspection</span>
          </div>
        </div>
      </div>
    </footer>
  );
};
