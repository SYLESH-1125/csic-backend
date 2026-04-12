
import AppChrome from '@/components/AppChrome';
import { FilterStateProvider } from '@/context/FilterStateProvider';

export default function MainLayout({ children }) {
  return (
    <FilterStateProvider>
      <AppChrome>{children}</AppChrome>
    </FilterStateProvider>
  );
}
