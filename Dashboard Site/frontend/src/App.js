import { useState } from "react";
import { Routes, Route, useLocation } from "react-router-dom";
import Topbar from "./scenes/global/Topbar";
import Sidebar from "./scenes/global/Sidebar";
import Dashboard from "./scenes/dashboard";
import Login from "./scenes/login";
import Team from "./scenes/team";
import Invoices from "./scenes/invoices";
import Contacts from "./scenes/contacts";
import URL from "./scenes/URL";
import Normal from "./scenes/normal";
import AnalysisResults from "./scenes/AnalysisResults";
import Ransomware from "./scenes/Ransomware";
import Bar from "./scenes/bar";
import Form from "./scenes/form";
import Line from "./scenes/line";
import Pie from "./scenes/pie";
import FileImport from './scenes/FileImport';
import FAQ from "./scenes/faq";
import AttackDetection from "./scenes/attacker_detection";
import Backdoors from "./scenes/Backdoors";
import Reconnaissance from "./scenes/reconnaissance";
import Shellcode from "./scenes/shellcode";
import Geography from "./scenes/geography";
import IoT from "./scenes/IoT";
import DoS from "./scenes/DoS";
import Exploits from "./scenes/Exploits";
import Generic from "./scenes/Generic";
import Analysis from "./scenes/Analysis";
import Worms from "./scenes/Worms";
import { CssBaseline, ThemeProvider } from "@mui/material";
import { ColorModeContext, useMode } from "./theme";
import Calendar from "./scenes/calendar/calendar";

function AppContent() {
  const [theme, colorMode] = useMode();
  const [isSidebar, setIsSidebar] = useState(true);
  const location = useLocation();
  const showSidebar = location.pathname !== "/login";

  return (
    <ColorModeContext.Provider value={colorMode}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <div className="app">
          {showSidebar && <Sidebar isSidebar={isSidebar} />}
          <main className="content">
            <Topbar setIsSidebar={setIsSidebar} />
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/team" element={<Team />} />
              <Route path="/contacts" element={<Contacts />} />
              <Route path="/invoices" element={<Invoices />} />
              <Route path="/form" element={<Form />} />
              <Route path="/bar" element={<Bar />} />
              <Route path="/pie" element={<Pie />} />
              <Route path="/line" element={<Line />} />
              <Route path="/faq" element={<FAQ />} />
              <Route path="/attacker_detection" element={<AttackDetection />}/>
              <Route path="/normal" element={<Normal />} />
              <Route path="/calendar" element={<Calendar />} />
              <Route path="/geography" element={<Geography />} />
              <Route path="/url" element={<URL />} />
              <Route path="/ransomware" element={<Ransomware />} />
              <Route path="/login" element={<Login />} />
              <Route path="/iot" element={<IoT />} />
              <Route path="/DoS" element={<DoS />} />
              <Route path="/AnalysisResults" element={<AnalysisResults />} />
              <Route path="/FileImport" element={<FileImport />} />
              <Route path="/shellcode" element={<Shellcode />} />
              <Route path="/reconnaissance" element={<Reconnaissance />} />
              <Route path="/Backdoors" element={<Backdoors />} />
              <Route path="/exploits" element={<Exploits />} />
              <Route path="/generic" element={<Generic />} />
              <Route path="/analysis" element={<Analysis />} />
              <Route path="/worms" element={<Worms />} />
            </Routes>
          </main>
        </div>
      </ThemeProvider>
    </ColorModeContext.Provider>
  );
}

function App() {
  return (
    <AppContent />
  );
}

export default App;