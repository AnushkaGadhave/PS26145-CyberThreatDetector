import { Component, type ErrorInfo, type ReactNode } from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';

interface ErrorBoundaryProps {
  children: ReactNode;
  fallbackTitle?: string;
  onReset?: () => void;
  onNavigateHome?: () => void;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Unhandled React Error in Component Tree:', error, errorInfo);
    this.setState({ errorInfo });
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    if (this.props.onReset) {
      this.props.onReset();
    }
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-[400px] flex items-center justify-center p-6 bg-[#07072B] font-mono">
          <div className="max-w-lg w-full bg-[#10103D]/90 border border-[#FF4D5A]/40 rounded-2xl p-6 shadow-2xl text-center space-y-4">
            <div className="w-12 h-12 rounded-xl bg-[#FF4D5A]/15 border border-[#FF4D5A]/30 flex items-center justify-center mx-auto text-[#FF4D5A]">
              <AlertTriangle className="w-6 h-6" />
            </div>

            <div className="space-y-1">
              <h3 className="font-heading font-extrabold text-lg text-[#F5F5F7]">
                {this.props.fallbackTitle || 'Telemetry View Encountered an Error'}
              </h3>
              <p className="text-xs text-[#A5A5BE]">
                An unexpected exception occurred while rendering this interface. The dashboard prevented a blank screen.
              </p>
            </div>

            {this.state.error && (
              <div className="p-3 rounded-xl bg-[#07072B] border border-[#242452] text-left text-[11px] text-[#FF4D5A] overflow-x-auto max-h-32">
                <span className="font-bold block mb-1">Diagnostic Details:</span>
                <code>{this.state.error.message || String(this.state.error)}</code>
              </div>
            )}

            <div className="flex items-center justify-center gap-3 pt-2">
              <button
                onClick={this.handleReset}
                className="px-4 py-2 rounded-xl bg-[#39D7FF]/20 hover:bg-[#39D7FF]/30 border border-[#39D7FF]/40 text-[#F5F5F7] text-xs font-bold transition-all cursor-pointer flex items-center gap-1.5"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Reset View</span>
              </button>

              {this.props.onNavigateHome && (
                <button
                  onClick={this.props.onNavigateHome}
                  className="px-4 py-2 rounded-xl bg-[#10103D] hover:bg-[#15154A] border border-[#242452] text-[#A5A5BE] hover:text-[#F5F5F7] text-xs transition-all cursor-pointer flex items-center gap-1.5"
                >
                  <Home className="w-3.5 h-3.5" />
                  <span>Return Home</span>
                </button>
              )}
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
