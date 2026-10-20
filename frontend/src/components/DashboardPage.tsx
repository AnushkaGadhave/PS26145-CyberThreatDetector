import React from 'react';
import { DashboardContainer } from './dashboard/DashboardContainer';

interface DashboardPageProps {
  onNavigate: (route: string) => void;
  currentRoute?: string;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({ onNavigate, currentRoute }) => {
  return <DashboardContainer onNavigate={onNavigate} currentRoute={currentRoute} />;
};

export default DashboardPage;
