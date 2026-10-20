import React, { useState, useEffect } from 'react';
import { Menu, X, ArrowRight, LogOut, User } from 'lucide-react';
import { useAuth } from '../context/AuthContext';


interface NavbarProps {
  onNavigate: (route: string) => void;
  currentRoute: string;
}

export const Navbar: React.FC<NavbarProps> = ({ onNavigate, currentRoute }) => {
  const { user, isAuthenticated, logout } = useAuth();
  const [scrolled, setScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const navLinks = [
    { name: 'Product', href: '#product' },
    { name: 'How It Works', href: '#how-it-works' },
    { name: 'Threat Detection', href: '#threat-detection' },
    { name: 'Architecture', href: '#architecture' },
    { name: 'Reports', href: '#explainable' },
  ];

  const handleLinkClick = (e: React.MouseEvent<HTMLAnchorElement>, href: string) => {
    e.preventDefault();
    setMobileMenuOpen(false);
    if (currentRoute !== '/') {
      onNavigate('/');
      setTimeout(() => {
        const el = document.querySelector(href);
        if (el) el.scrollIntoView({ behavior: 'smooth' });
      }, 100);
    } else {
      const el = document.querySelector(href);
      if (el) el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <header
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        scrolled
          ? 'bg-[#07072B]/90 backdrop-blur-md border-b border-[#242452] shadow-lg shadow-black/40 py-3.5'
          : 'bg-[#07072B]/60 backdrop-blur-sm border-b border-[#242452]/60 py-5'
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between">
          {/* Left Brand Identity */}
          <button
            onClick={() => onNavigate('/')}
            className="flex items-center gap-3 text-left group focus:outline-none"
            aria-label="NETRA Home"
          >
            <div className="relative w-9 h-9 rounded-lg bg-[#10103D] border border-[#242452] flex items-center justify-center group-hover:border-[#A8F500]/60 transition-colors">
              <div className="w-2.5 h-2.5 rounded-full bg-[#A8F500] animate-ping-dot absolute" />
              <div className="w-2 h-2 rounded-full bg-[#A8F500]" />
              <div className="absolute inset-0 border border-[#A8F500]/20 rounded-lg scale-90 group-hover:scale-100 transition-transform" />
            </div>
            <div className="flex flex-col">
              <span className="font-heading font-extrabold text-lg tracking-tight text-[#F5F5F7] flex items-center gap-1.5">
                NETRA
                <span className="inline-block w-1.5 h-1.5 rounded-full bg-[#A8F500]" />
              </span>
              <span className="text-[11px] font-medium tracking-normal text-[#A5A5BE] -mt-0.5 hidden sm:block">
                Passive Network Threat Monitoring
              </span>
            </div>
          </button>

          {/* Center Navigation Links (Desktop) */}
          <nav className="hidden md:flex items-center gap-1 lg:gap-2 bg-[#10103D]/60 border border-[#242452]/80 px-3 py-1.5 rounded-full backdrop-blur-sm">
            {navLinks.map((link) => (
              <a
                key={link.name}
                href={link.href}
                onClick={(e) => handleLinkClick(e, link.href)}
                className="text-xs lg:text-[13px] font-medium text-[#A5A5BE] hover:text-[#F5F5F7] px-3 py-1.5 rounded-full hover:bg-[#15154A] transition-all"
              >
                {link.name}
              </a>
            ))}
          </nav>

          {/* Right Action Buttons */}
          <div className="hidden sm:flex items-center gap-2.5 lg:gap-3">
            {isAuthenticated && user ? (
              <div className="flex items-center gap-2">
                <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#10103D] border border-[#242452] text-xs font-mono">
                  <User className="w-3.5 h-3.5 text-[#39D7FF]" />
                  <span className="text-[#F5F5F7] max-w-[120px] truncate">{user.full_name || user.email}</span>
                  <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold ${user.role === 'admin' ? 'bg-[#A8F500]/20 text-[#A8F500]' : 'bg-[#39D7FF]/20 text-[#39D7FF]'}`}>
                    {user.role.toUpperCase()}
                  </span>
                </div>
                <button
                  onClick={async () => {
                    await logout();
                    onNavigate('/');
                  }}
                  className="text-xs font-mono text-[#A5A5BE] hover:text-[#FF4D5A] p-2 rounded-lg hover:bg-[#10103D] border border-transparent hover:border-[#FF4D5A]/30 transition-colors cursor-pointer"
                  title="Sign Out"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            ) : (
              <button
                onClick={() => onNavigate('/login')}
                className="text-xs lg:text-sm font-medium text-[#A5A5BE] hover:text-[#F5F5F7] px-3.5 py-2 rounded-lg hover:bg-[#10103D] border border-transparent hover:border-[#242452] transition-all cursor-pointer"
              >
                Sign In
              </button>
            )}
            <button
              onClick={() => onNavigate('/dashboard')}
              className="group relative inline-flex items-center gap-2 text-xs lg:text-sm font-semibold text-[#07072B] bg-[#A8F500] hover:bg-[#B7FF19] px-4 py-2 rounded-lg transition-all duration-200 shadow-sm hover:shadow-[#A8F500]/20 hover:shadow-md cursor-pointer"
            >
              <span>Security Console</span>
              <ArrowRight className="w-3.5 h-3.5 transition-transform group-hover:translate-x-0.5" />
            </button>
          </div>

          {/* Mobile Hamburger Toggle */}
          <div className="flex sm:hidden items-center gap-2">
            {!isAuthenticated && (
              <button
                onClick={() => onNavigate('/login')}
                className="text-xs font-medium text-[#A5A5BE] px-2.5 py-1.5 rounded-md hover:bg-[#10103D] border border-[#242452]"
              >
                Sign In
              </button>
            )}
            <button
              onClick={() => onNavigate('/dashboard')}
              className="text-xs font-semibold text-[#07072B] bg-[#A8F500] px-3 py-1.5 rounded-md"
            >
              Console →
            </button>
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-2 text-[#A5A5BE] hover:text-[#F5F5F7] rounded-lg hover:bg-[#10103D] border border-[#242452]"
              aria-label="Toggle navigation menu"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Menu Dropdown */}
      {mobileMenuOpen && (
        <div className="sm:hidden bg-[#0B0B35]/95 border-b border-[#242452] px-5 py-6 space-y-4 backdrop-blur-xl mt-3 animate-fadeIn">
          <div className="flex flex-col space-y-2">
            {navLinks.map((link) => (
              <a
                key={link.name}
                href={link.href}
                onClick={(e) => handleLinkClick(e, link.href)}
                className="text-sm font-medium text-[#A5A5BE] hover:text-[#A8F500] py-2 px-3 rounded-md hover:bg-[#10103D] transition-colors"
              >
                {link.name}
              </a>
            ))}
          </div>
          <div className="pt-4 border-t border-[#242452] flex flex-col gap-2.5">
            {isAuthenticated && user ? (
              <>
                <div className="flex items-center justify-between px-3 py-2 rounded-lg bg-[#10103D] border border-[#242452] text-xs font-mono">
                  <span className="text-[#F5F5F7] truncate">{user.email}</span>
                  <span className="text-[10px] text-[#A8F500] font-bold uppercase">{user.role}</span>
                </div>
                <button
                  onClick={async () => {
                    setMobileMenuOpen(false);
                    await logout();
                    onNavigate('/');
                  }}
                  className="w-full text-center text-sm font-medium text-[#FF4D5A] py-2 rounded-lg bg-[#FF4D5A]/10 border border-[#FF4D5A]/30 transition-colors"
                >
                  Sign Out
                </button>
              </>
            ) : (
              <button
                onClick={() => {
                  setMobileMenuOpen(false);
                  onNavigate('/login');
                }}
                className="w-full text-center text-sm font-medium text-[#F5F5F7] py-2.5 rounded-lg bg-[#10103D] border border-[#242452] hover:border-[#39D7FF]/40 transition-colors"
              >
                Sign In
              </button>
            )}
            <button
              onClick={() => {
                setMobileMenuOpen(false);
                onNavigate('/dashboard');
              }}
              className="w-full text-center text-sm font-semibold text-[#07072B] py-2.5 rounded-lg bg-[#A8F500] hover:bg-[#B7FF19] flex items-center justify-center gap-2"
            >
              <span>Security Console</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </header>
  );
};
