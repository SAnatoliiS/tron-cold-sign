import { BrowserRouter, Route, Routes } from "react-router-dom";
import { I18nProvider } from "@/lib/i18n";
import { AppLayout } from "@/components/AppLayout";
import Home from "@/pages/Home";
import CreateFlow from "@/pages/CreateFlow";
import BroadcastFlow from "@/pages/BroadcastFlow";
import NotFound from "@/pages/NotFound";

const App = () => (
  <I18nProvider>
    <BrowserRouter>
      <AppLayout>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/create" element={<CreateFlow />} />
          <Route path="/broadcast" element={<BroadcastFlow />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </AppLayout>
    </BrowserRouter>
  </I18nProvider>
);

export default App;
