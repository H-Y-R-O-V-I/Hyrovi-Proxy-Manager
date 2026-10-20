import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { lazy, Suspense } from "react";
import EasyModal from "ez-modal-react";
import { RawIntlProvider } from "react-intl";
import { ToastContainer } from "react-toastify";
import { AuthProvider, LocaleProvider, ThemeProvider } from "src/context";
import { getLocale, intl, isRTLLocale } from "src/locale";
import Router from "src/Router.tsx";

// Never load query debugging tools in the publicly served production bundle.
// Loading devtools unconditionally made their pane cover mobile HPM screens.
const DevelopmentQueryTools = import.meta.env.DEV
	? lazy(() => import("./DevelopmentQueryTools"))
	: null;

// Create a client
const queryClient = new QueryClient();

function App() {
	return (
		<RawIntlProvider value={intl}>
			<LocaleProvider>
				<ThemeProvider>
					<QueryClientProvider client={queryClient}>
						<AuthProvider>
							<EasyModal.Provider>
								<Router />
							</EasyModal.Provider>
							<ToastContainer
								position="top-right"
								autoClose={5000}
								hideProgressBar={true}
								newestOnTop={true}
								closeOnClick={true}
								rtl={isRTLLocale(getLocale())}
								closeButton={false}
							/>
						</AuthProvider>
						{DevelopmentQueryTools ? (
							<Suspense fallback={null}>
								<DevelopmentQueryTools />
							</Suspense>
						) : null}
					</QueryClientProvider>
				</ThemeProvider>
			</LocaleProvider>
		</RawIntlProvider>
	);
}

export default App;
