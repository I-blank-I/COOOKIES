import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.ui.settings.SettingsPanelBuilder;
import burp.api.montoya.ui.settings.SettingsPanelPersistence;
import burp.api.montoya.ui.settings.SettingsPanelSetting;
import burp.api.montoya.ui.settings.SettingsPanelWithData;

import burp.api.montoya.ui.hotkey.HotKeyContext;
import burp.api.montoya.ui.hotkey.HotKeyHandler;
import burp.api.montoya.ui.hotkey.HotKey;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;
import javax.swing.table.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;
import java.util.regex.*;
import java.net.URL;
import java.io.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.SynchronousQueue;

public class Coookies implements BurpExtension, HttpHandler, ContextMenuItemsProvider {
    private MontoyaApi api;
    private JPanel mainPanel;
    private DefaultListModel<PipelineRequest> requestListModel;
    private JList<PipelineRequest> requestList;
    private HttpRequestEditor rawRequestEditor;
    private HttpResponseEditor rawResponseEditor;
    private JPanel extractionPanel;
    private DefaultTableModel credentialsTableModel;
    private JTable credentialsTable;
    private DefaultTableModel staticVarsTableModel;
    private JTable staticVarsTable;
    private DefaultTableModel autoAuthHeadersTableModel;
    private JTable autoAuthHeadersTable;
    private static final String AUTO_AUTH_TRIGGER_HEADER = "X-Auto-Authorization";
    private JTextArea logArea;
    private JTextArea availableVarsArea;
    private List<PipelineRequest> pipeline;
    private int selectedRequestIndex = -1;
    private JTextArea expirationStringsArea;
    private List<String> expirationStrings;
    private final java.util.concurrent.atomic.AtomicBoolean pipelineRunning = new java.util.concurrent.atomic.AtomicBoolean(false);
    private JButton executeBtn;
    private static final long AUTO_LOGIN_COOLDOWN_MS = 5000;
    private volatile long lastLoginFinishedAt = 0;
    private volatile long nextTimerRunAtMillis = 0;

    private PipelineRequest editorOwner;

    private Map<String, Map<String, String>> extractedValues;
    private final Map<Integer, String> modifiedRequests = Collections.synchronizedMap(new HashMap<>());
    private Map<String, String> finalAuthValues;
    private boolean updateContentLength = false;
    private boolean interceptionEnabled = false;
    private boolean proxyTool = false;
    private boolean proxyToolRes = false;
    private JToggleButton interceptionToggle;
    private JToggleButton ContentLengthToggle;
    private JToggleButton proxyToggle;
    private JToggleButton proxyToggleRes;

    private EasterEggPlayer easterEggPlayer;
    private int   eggClickCount      = 0;
    private long  eggFirstClickTime  = 0;
    private static final int  EGG_CLICKS_NEEDED = 10;
    private static final long EGG_CLICK_WINDOW  = 3000;

    private JTextField defaultPortField;
    private JCheckBox forceHttpsCheckbox;
    private static final String DEFAULT_SWITCH_USER_HOTKEY = "Ctrl+Shift+C";
    private static final String DEFAULT_EXECUTE_PIPELINE_HOTKEY = "Ctrl+Shift+Equals";
    private String executePipelineHotkey = DEFAULT_EXECUTE_PIPELINE_HOTKEY;
    private int configuredPort = 443;
    private boolean configuredHttps = true;

    private JLabel statusLabel;
    private volatile int  pipelineActiveCredRow = -1;
    private volatile int  pipelineActiveReqRow  = -1;


    private CardLayout stepDetailLayout;
    private JPanel stepDetailContainer;
    private JPanel checkpointVarsList;
    private JButton addCheckpointVarBtn;
    private JButton checkpointContinueBtn;
    private JLabel checkpointStatusLabel;
    private final Map<String, JTextField> checkpointValueFields = new HashMap<>();
    private final BlockingQueue<Boolean> checkpointContinueSignal = new SynchronousQueue<>();
    private volatile boolean awaitingCheckpoint = false;
    private volatile int awaitingCheckpointStepIdx = -1;
    private volatile Map<String, String> pendingCheckpointValues = null;


    private static final String REFRESH_TOKEN_VAR = "REFRESH_TOKEN";
    private List<PipelineRequest> refreshPipeline;
    private boolean showingRefresh = false;              // which pipeline the step list is showing
    private volatile boolean activeRunIsRefresh = false; // which pipeline the worker is running
    /** How sessions are kept alive. Exactly one of these at a time, or none. */
    enum SessionMode {
        OFF("Off", false),
        EXPIRATION_STRINGS("Expiration strings", false),
        LOGIN_TIMER("Login timer", true),
        REFRESH_TIMER("Refresh timer", true);

        final String label;
        final boolean timer;

        SessionMode(String label, boolean timer) {
            this.label = label;
            this.timer = timer;
        }

        @Override public String toString() { return label; }
    }

    private volatile SessionMode sessionMode = SessionMode.OFF;
    private JComboBox<SessionMode> sessionModeCombo;
    private boolean updatingModeCombo = false;
    private boolean applyingConfig = false;
    private volatile int timerIntervalMinutes = 60;
    private final Map<String, Map<String, String>> cookieJars = new java.util.concurrent.ConcurrentHashMap<>();
    private java.util.concurrent.ScheduledExecutorService refreshScheduler;
    private java.util.concurrent.ScheduledFuture<?> refreshTask;
    private JToggleButton loginViewBtn;
    private JToggleButton refreshViewBtn;
    private JButton addStepTypeBtn;
    private JPanel refreshControls;
    private JSpinner timerIntervalSpinner;
    private JButton refreshNowBtn;
    private JLabel timerStatusLabel;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.pipeline = new ArrayList<>();
        this.refreshPipeline = new ArrayList<>();

        this.extractedValues = new java.util.concurrent.ConcurrentHashMap<>();
        this.finalAuthValues = new java.util.concurrent.ConcurrentHashMap<>();
        this.expirationStrings = new ArrayList<>();

        api.extension().setName("COOOKIES");
        api.http().registerHttpHandler(this);
        api.userInterface().registerContextMenuItemsProvider(this);
        api.extension().registerUnloadingHandler(this::shutdownSessionTimer);

        SettingsPanelWithData panel = SettingsPanelBuilder.settingsPanel()
            .withPersistence(SettingsPanelPersistence.USER_SETTINGS)
            .withTitle("COOOKIES Settings")
            .withDescription("IMPORTANT: after editing the Hotkey reload the extension to apply changes")
            .withSettings(
                SettingsPanelSetting.stringSetting("Switch User Hotkey", DEFAULT_SWITCH_USER_HOTKEY),
                SettingsPanelSetting.stringSetting("Execute Pipeline Hotkey", DEFAULT_EXECUTE_PIPELINE_HOTKEY)
                )
            .build();
        api.userInterface().registerSettingsPanel(panel);


        String preferredHotkey = panel.getString("Switch User Hotkey");
        if (preferredHotkey == null || preferredHotkey.trim().isEmpty()) {
            preferredHotkey = DEFAULT_SWITCH_USER_HOTKEY;
        } else {
            preferredHotkey = preferredHotkey.trim();
        }
        String savedExecHotkey = panel.getString("Execute Pipeline Hotkey");
        if (savedExecHotkey != null && !savedExecHotkey.trim().isEmpty()) {
            executePipelineHotkey = savedExecHotkey.trim();
        }

        api.logging().logToOutput("Switch User Hotkey loaded: "+preferredHotkey);
        api.logging().logToOutput("Execute Pipeline Hotkey loaded: "+executePipelineHotkey);

        HotKeyHandler rollHandler = event -> event.messageEditorRequestResponse().ifPresent(editor -> {
            try {
                HttpRequest request = editor.requestResponse().request();
                String requestStr = request.toString();

                if (!requestStr.contains("<__COOOKIES__:") && !requestStr.contains("<COOOKIES:")) {
                    return;
                }

                List<String> usernames = new ArrayList<>();
                for (int i = 0; i < credentialsTableModel.getRowCount(); i++) {
                    String username = (String) credentialsTableModel.getValueAt(i, 0);
                    if (username != null && !username.trim().isEmpty()) {
                        usernames.add(username.trim());
                    }
                }

                if (usernames.isEmpty()) return;

                String currentUsername = extractCurrentUsername(requestStr, usernames);
                if (currentUsername == null) return;

                int currentIndex = usernames.indexOf(currentUsername);
                int nextIndex = (currentIndex + 1) % usernames.size();
                String nextUsername = usernames.get(nextIndex);

                String newRequestStr = rollUsernameInPatterns(requestStr, currentUsername, nextUsername);

                HttpRequest newRequest = HttpRequest.httpRequest(newRequestStr);
                if (request.httpService() != null) {
                    newRequest = newRequest.withService(request.httpService());
                }

                editor.setRequest(newRequest);

            } catch (Exception e) {

            }
        });

        registerHotKey("Roll to next credential", preferredHotkey, DEFAULT_SWITCH_USER_HOTKEY, rollHandler);

        HotKeyHandler executeHandler = event -> SwingUtilities.invokeLater(() -> {
            executePipeline();
            setInterception(true);
        });
        registerHotKey("Execute COOOKIES Pipeline", executePipelineHotkey, DEFAULT_EXECUTE_PIPELINE_HOTKEY, executeHandler);

        SwingUtilities.invokeLater(() -> {
            mainPanel = new JPanel(new BorderLayout());

            rawRequestEditor = api.userInterface().createHttpRequestEditor();
            rawResponseEditor = api.userInterface().createHttpResponseEditor();

            mainPanel.add(buildHeader(),  BorderLayout.NORTH);
            mainPanel.add(buildCenter(),  BorderLayout.CENTER);
            mainPanel.add(buildLogDrawer(), BorderLayout.SOUTH);

            api.userInterface().registerSuiteTab("COOOKIES", mainPanel);
            loadFromProject();
            attachEasterEggListener();
        });
    }

    /** Registers a hotkey; if Burp rejects the configured binding, retries with the default instead of
     *  letting the exception abort extension startup. */
    private void registerHotKey(String name, String configured, String fallback, HotKeyHandler handler) {
        try {
            api.userInterface().registerHotKeyHandler(
                HotKeyContext.HTTP_MESSAGE_EDITOR, HotKey.hotKey(name, configured), handler);
            return;
        } catch (Exception e) {
            api.logging().logToError("[COOOKIES] Could not register hotkey '" + configured + "' for \"" + name + "\": " + e.getMessage());
        }

        if (fallback.equals(configured)) return;
        try {
            api.userInterface().registerHotKeyHandler(
                HotKeyContext.HTTP_MESSAGE_EDITOR, HotKey.hotKey(name, fallback), handler);
            api.logging().logToOutput("[COOOKIES] Using default hotkey '" + fallback + "' for \"" + name + "\".");
        } catch (Exception e) {
            api.logging().logToError("[COOOKIES] Could not register default hotkey '" + fallback + "' for \"" + name + "\": " + e.getMessage());
        }
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        if (interceptionEnabled) {
            try {
                HttpRequest currentRequest = requestToBeSent;



                // "X-Auto-Authorization: <username>" is an internal-only trigger: it is always stripped,
                // and the configured header rules are applied for that user in its place.
                String autoAuthValue = findHeaderValue(requestToBeSent, AUTO_AUTH_TRIGGER_HEADER);
                if (autoAuthValue != null) {
                    String requestedUser = autoAuthValue.trim();
                    List<String[]> autoAuthHeaders;
                    if (hasSession(requestedUser)) {
                        autoAuthHeaders = new ArrayList<>();
                        for (String[] rule : getConfiguredAutoAuthHeaders()) {
                            autoAuthHeaders.add(new String[]{
                                bindAutoAuthUser(rule[0], requestedUser), bindAutoAuthUser(rule[1], requestedUser)});
                        }
                    } else if (requestedUser.equals("1")) {
                        autoAuthHeaders = getConfiguredAutoAuthHeaders(); // legacy trigger: rules applied as written
                    } else {
                        autoAuthHeaders = new ArrayList<>();
                        api.logging().logToError("[COOOKIES] Auto-Authorization: no COOOKIES session for user '" +
                                requestedUser + "'; trigger header removed, no headers added.");
                    }
                    String rebuiltRaw = applyAutoAuthHeaders(currentRequest.toString(), autoAuthHeaders);

                    HttpRequest rebuiltRequest = HttpRequest.httpRequest(rebuiltRaw);
                    if (requestToBeSent.httpService() != null) {
                        rebuiltRequest = rebuiltRequest.withService(requestToBeSent.httpService());
                    }
                    currentRequest = rebuiltRequest;

                    api.logging().logToOutput("Auto-Authorization triggered for '" + requestedUser + "'; applied " +
                            autoAuthHeaders.size() + " configured header(s). Request headers now: " +
                            currentRequest.headers().stream().map(HttpHeader::name).reduce((a, b) -> a + ", " + b).orElse("(none)"));
                }

                String requestStr = currentRequest.toString();

                if (!containsPatterns(requestStr)) {
                    return RequestToBeSentAction.continueWith(currentRequest);
                }

                String[] resp = replacePatterns(requestStr);

                String username = resp[0];
                String modifiedRequest = resp[1];
                logUnresolvedPatterns(modifiedRequest);

                if (!modifiedRequest.equals(requestStr)) {
                    HttpRequest newRequest = HttpRequest.httpRequest(modifiedRequest);

                    if (updateContentLength) {
                        int bodyOffset = modifiedRequest.indexOf("\r\n\r\n");
                        if (bodyOffset != -1) {
                            String body = modifiedRequest.substring(bodyOffset + 4);
                            int newBodyLength = body.getBytes().length;
                            newRequest = newRequest.withUpdatedHeader("Content-Length", String.valueOf(newBodyLength));
                        }
                    }

                    if (requestToBeSent.httpService() != null) {
                        newRequest = newRequest.withService(requestToBeSent.httpService());
                    }

                    modifiedRequests.put(requestToBeSent.messageId(), username);

                    api.logging().logToOutput("Replaced patterns in request from tool: " + requestToBeSent.toolSource().toolType());
                    return RequestToBeSentAction.continueWith(newRequest);
                }

                return RequestToBeSentAction.continueWith(currentRequest);
            } catch (Exception e) {
                api.logging().logToError("Error in HTTP interception: " + e.getMessage());
                e.printStackTrace();
            }
        }

        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    /** Header lookup by name, ignoring case: HTTP/2 requests carry lowercase header names. */
    private String findHeaderValue(HttpRequest request, String name) {
        for (HttpHeader header : request.headers()) {
            if (header.name().trim().equalsIgnoreCase(name)) return header.value();
        }
        return null;
    }

    private static final Pattern ANY_COOOKIES_PATTERN = Pattern.compile("<__COOOKIES__:[^>]+>|<COOOKIES:[^>]+>");

    /** Patterns still present after replacement are sent to the server literally; say which ones and why. */
    private void logUnresolvedPatterns(String request) {
        Set<String> unresolved = new LinkedHashSet<>();
        Matcher m = ANY_COOOKIES_PATTERN.matcher(request);
        while (m.find()) unresolved.add(m.group());
        if (!unresolved.isEmpty()) {
            api.logging().logToError("[COOOKIES] Unresolved pattern(s) sent as-is: " + String.join(", ", unresolved) +
                " (no value for that user/variable yet: has the login pipeline run and extracted it?)");
        }
    }

    private boolean containsPatterns(String request) {
        if (request.contains("<__COOOKIES__:")) {
            return true;
        }
        if (request.contains("<COOOKIES:")) {
            return true;
        }
        return false;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        HttpResponse currentResponse = responseReceived;

        if (interceptionEnabled) {
            try {
                String username = modifiedRequests.remove(responseReceived.messageId());
                if (username != null) {
                    currentResponse = currentResponse.withAddedHeader(
                        "Coookies-Authenticated-User", 
                        username
                    );
                }
            } catch (Exception e) {
                api.logging().logToError("Error in response interception: " + e.getMessage());
            }
        }

        if (sessionMode == SessionMode.EXPIRATION_STRINGS) {

            try {
                String responseStr = currentResponse.toString();

                boolean hasExpired = false;
                synchronized (expirationStrings) {
                    for (String expirationString : expirationStrings) {
                        if (responseStr.contains(expirationString)) {
                            hasExpired = true;
                            api.logging().logToOutput("Session expiration detected: found string '" + expirationString + "'");
                            break;
                        }
                    }
                }

                if (hasExpired) {


                    HttpResponse modifiedResponse = currentResponse.withAddedHeader("Coookies-Expiration", "HIT");



                    boolean coolingDown = System.currentTimeMillis() - lastLoginFinishedAt < AUTO_LOGIN_COOLDOWN_MS;

                    if (!pipelineRunning.get() && !coolingDown) {
                        api.logging().logToOutput("Starting automatic pipeline execution due to session expiration");

                        new Thread(() -> {
                            try {
                                runPipelineExclusive(false);
                            } catch (Exception e) {
                                api.logging().logToError("Error during automatic pipeline execution: " + e.getMessage());
                                e.printStackTrace();
                            } finally {
                                api.logging().logToOutput("Automatic pipeline execution completed");
                            }
                        }).start();
                    } else {
                        api.logging().logToOutput("Pipeline running or just finished, skipping automatic execution");
                    }

                    return ResponseReceivedAction.continueWith(modifiedResponse);
                }

            } catch (Exception e) {
                api.logging().logToError("Error in HTTP response interception: " + e.getMessage());
                e.printStackTrace();
            }
        }

        return ResponseReceivedAction.continueWith(currentResponse);
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        if (!event.isFromTool(ToolType.REPEATER) && 
            !event.isFromTool(ToolType.PROXY) && 
            !event.isFromTool(ToolType.INTRUDER)) {

            Optional<MessageEditorHttpRequestResponse> messageEditor = event.messageEditorRequestResponse();
            if (!messageEditor.isPresent()) {
                return menuItems;
            }
        }

        JMenu coookiesMenu = new JMenu("COOOKIES Patterns");

        if (!finalAuthValues.isEmpty()) {
            JMenu authMenu = new JMenu("Final Auth Values");
            for (Map.Entry<String, String> entry : finalAuthValues.entrySet()) {
                String pattern = "<__COOOKIES__:" + entry.getKey() + ">";
                JMenuItem item = new JMenuItem(pattern);
                item.addActionListener(e -> insertPattern(event, pattern));
                authMenu.add(item);
            }
            menuItems.add(authMenu);
        }

        if (!extractedValues.isEmpty()) {
            for (Map.Entry<String, Map<String, String>> userEntry : extractedValues.entrySet()) {
                String username = userEntry.getKey();
                Map<String, String> vars = userEntry.getValue();

                if (!vars.isEmpty()) {
                    JMenu userMenu = new JMenu("User: " + username);
                    for (String varName : vars.keySet()) {
                        String pattern = "<COOOKIES:" + username + ":" + varName + ">";
                        JMenuItem item = new JMenuItem(varName + " → " + pattern);
                        item.addActionListener(e -> insertPattern(event, pattern));
                        userMenu.add(item);
                    }
                    menuItems.add(userMenu);
                }
            }
        }

        return menuItems;
    }

    private void insertPattern(ContextMenuEvent event, String pattern) {
        try {
            Optional<MessageEditorHttpRequestResponse> messageEditor = event.messageEditorRequestResponse();
            if (!messageEditor.isPresent()) {
                return;
            }

            MessageEditorHttpRequestResponse editor = messageEditor.get();
            HttpRequest request = editor.requestResponse().request();

            Optional<burp.api.montoya.core.Range> selection = editor.selectionOffsets();
            String requestStr = request.toString();

            if (selection.isPresent()) {
                burp.api.montoya.core.Range range = selection.get();
                String before = requestStr.substring(0, range.startIndexInclusive());
                String after = requestStr.substring(range.endIndexExclusive());
                String modified = before + pattern + after;

                HttpRequest modifiedRequest = HttpRequest.httpRequest(modified);

                if (request.httpService() != null) {
                    modifiedRequest = modifiedRequest.withService(request.httpService());
                }

                editor.setRequest(modifiedRequest);
                api.logging().logToOutput("Inserted pattern: " + pattern);
            } else {
                api.logging().logToOutput("No selection found. Pattern copied to clipboard: " + pattern);

                java.awt.datatransfer.StringSelection stringSelection = new java.awt.datatransfer.StringSelection(pattern);
                java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, null);

                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(
                        null,
                        "Pattern copied to clipboard!\n\nSelect text in the editor and use this menu to replace,\nor paste manually with Ctrl+V",
                        "Pattern Ready",
                        JOptionPane.INFORMATION_MESSAGE
                    );
                });
            }
        } catch (Exception e) {
            api.logging().logToError("Error inserting pattern: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private String[] replacePatterns(String request) {
        String result = request;

        Pattern authPattern = Pattern.compile("<__COOOKIES__:([^>]+)>");
        Matcher authMatcher = authPattern.matcher(result);
        StringBuffer sb = new StringBuffer();
        String auth_username = "";
        String params_username = "";
        String username = "";

        while (authMatcher.find()) {
            auth_username = authMatcher.group(1);
            String replacement = finalAuthValues.getOrDefault(auth_username, authMatcher.group(0));
            authMatcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        authMatcher.appendTail(sb);
        result = sb.toString();

        Pattern varPattern = Pattern.compile("<COOOKIES:([^:>]+):([^>]+)>");
        Matcher varMatcher = varPattern.matcher(result);
        sb = new StringBuffer();

        while (varMatcher.find()) {
            params_username = varMatcher.group(1);
            String varName = varMatcher.group(2);

            Map<String, String> userVars = extractedValues.get(params_username);
            String replacement = varMatcher.group(0);

            if (userVars != null && userVars.containsKey(varName)) {
                replacement = userVars.get(varName);
            }

            varMatcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        varMatcher.appendTail(sb);
        result = sb.toString();

        if (auth_username!="" || (params_username!="" && auth_username.equals(params_username))){
            username = auth_username;
        }

        String[] resp = new String[]{username, result};

        return resp;
    }



    /** Top header bar: title + pipeline action buttons + interception toggles */
    private JPanel buildHeader() {
        JPanel bar = new JPanel(new BorderLayout());
        bar.setBorder(new CompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0,
                UIManager.getColor("Separator.foreground")),
            BorderFactory.createEmptyBorder(8, 14, 8, 14)));


        JLabel title = new JLabel("COOOKIES");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 15f));
        bar.add(title, BorderLayout.WEST);


        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        right.setOpaque(false);

        executeBtn = new JButton("▶  Execute Pipeline");
        executeBtn.setFont(executeBtn.getFont().deriveFont(Font.BOLD, 12f));
        executeBtn.setFocusPainted(false);
        executeBtn.addActionListener(e -> executePipeline());

        JButton exportBtn = new JButton("⬆ Export");
        JButton importBtn = new JButton("⬇ Import");
        JButton saveBtn   = new JButton("💾 Save");
        for (JButton b : new JButton[]{exportBtn, importBtn, saveBtn}) {
            b.setFont(b.getFont().deriveFont(11f));
            b.setFocusPainted(false);
        }
        exportBtn.addActionListener(e -> exportPipeline());
        importBtn.addActionListener(e -> importPipeline());
        saveBtn.addActionListener(e -> {
            saveToProject();
            JOptionPane.showMessageDialog(mainPanel,
                "Configuration saved to Burp project file!\n\nIt will be automatically restored next time you open this project.",
                "Saved to Project", JOptionPane.INFORMATION_MESSAGE);
        });

        JSeparator sep1 = new JSeparator(JSeparator.VERTICAL);
        sep1.setPreferredSize(new Dimension(1, 20));
        JSeparator sep2 = new JSeparator(JSeparator.VERTICAL);
        sep2.setPreferredSize(new Dimension(1, 20));

        interceptionToggle = new JToggleButton("Req Intercept: OFF");
        interceptionToggle.setFont(interceptionToggle.getFont().deriveFont(Font.BOLD, 11f));
        interceptionToggle.setFocusPainted(false);
        interceptionToggle.addActionListener(e -> setInterception(interceptionToggle.isSelected()));

        ContentLengthToggle = new JToggleButton("Content-Length: OFF");
        ContentLengthToggle.setFont(ContentLengthToggle.getFont().deriveFont(Font.BOLD, 11f));
        ContentLengthToggle.setFocusPainted(false);
        ContentLengthToggle.addActionListener(e -> {
            updateContentLength = ContentLengthToggle.isSelected();
            ContentLengthToggle.setText("Content-Length: " + (updateContentLength ? "ON" : "OFF"));
            ContentLengthToggle.setBackground(updateContentLength ? new Color(144, 238, 144) : null);
        });

        sessionModeCombo = new JComboBox<>(SessionMode.values());
        sessionModeCombo.setFont(sessionModeCombo.getFont().deriveFont(Font.BOLD, 11f));
        sessionModeCombo.setFocusable(false);
        sessionModeCombo.setToolTipText("<html>How sessions are kept alive (one at a time):<br>"
            + "<b>Expiration strings</b>: re-run the login pipeline when a response contains one of the Settings strings<br>"
            + "<b>Login timer</b>: re-run the login pipeline every N minutes<br>"
            + "<b>Refresh timer</b>: run the Refresh pipeline every N minutes<br>"
            + "Timers start when a login run finishes.</html>");
        sessionModeCombo.addActionListener(e -> {
            if (updatingModeCombo) return;
            SessionMode chosen = (SessionMode) sessionModeCombo.getSelectedItem();
            if (chosen == SessionMode.REFRESH_TIMER) {
                String problem = !hasRefreshTokenExtraction()
                    ? "Add a Refresh Token Extraction to a Login step first: it unlocks the Refresh pipeline."
                    : refreshPipeline.isEmpty()
                        ? "The Refresh pipeline has no steps yet.\nSwitch the pipeline list to \"Refresh\" and add at least one request."
                        : null;
                if (problem != null) {
                    JOptionPane.showMessageDialog(mainPanel, problem, "Refresh timer", JOptionPane.WARNING_MESSAGE);
                    chosen = sessionMode;
                }
            }
            setSessionMode(chosen);
            saveToProject();
        });

        timerIntervalSpinner = new JSpinner(new SpinnerNumberModel(timerIntervalMinutes, 1, 100000, 1));
        timerIntervalSpinner.setToolTipText("Minutes between timed runs (counted from the end of the previous run)");
        timerIntervalSpinner.setEnabled(false);
        timerIntervalSpinner.addChangeListener(e -> {
            int previousMinutes = timerIntervalMinutes;
            timerIntervalMinutes = (Integer) timerIntervalSpinner.getValue();
            if (isSessionTimerScheduled()) {
                // Apply the new interval to the running countdown without restarting it
                nextTimerRunAtMillis += (timerIntervalMinutes - previousMinutes) * 60_000L;
                setTimerStatus(nextTimerRunText(), null);
            }
            if (!applyingConfig) saveToProject();
        });

        timerStatusLabel = new JLabel("");
        timerStatusLabel.setFont(timerStatusLabel.getFont().deriveFont(Font.ITALIC, 11f));
        timerStatusLabel.setForeground(UIManager.getColor("Label.disabledForeground"));

        JPanel sessionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        sessionPanel.setOpaque(false);
        sessionPanel.add(new JLabel("Session:"));
        sessionPanel.add(sessionModeCombo);
        sessionPanel.add(new JLabel("every"));
        sessionPanel.add(timerIntervalSpinner);
        sessionPanel.add(new JLabel("min"));
        sessionPanel.add(timerStatusLabel);

        right.add(interceptionToggle);
        right.add(ContentLengthToggle);
        right.add(sessionPanel);
        right.add(sep1);
        right.add(importBtn);
        right.add(exportBtn);
        right.add(saveBtn);
        right.add(sep2);
        right.add(executeBtn);

        bar.add(right, BorderLayout.EAST);
        return bar;
    }

    private void setInterception(boolean enabled) {
        interceptionEnabled = enabled;
        interceptionToggle.setSelected(enabled);
        interceptionToggle.setText("Req Intercept: " + (enabled ? "ON" : "OFF"));
        interceptionToggle.setBackground(enabled ? new Color(144, 238, 144) : null);
    }

    /**
     * Switches how sessions are kept alive. Choosing a timer mode never starts the timer by itself:
     * the countdown starts when a login run finishes (see afterLoginRun). Leaving a mode stops its timer.
     */
    private void setSessionMode(SessionMode mode) {
        if (mode == SessionMode.REFRESH_TIMER && !hasRefreshTokenExtraction()) mode = SessionMode.OFF;

        SessionMode previous = sessionMode;
        sessionMode = mode;

        updatingModeCombo = true;
        sessionModeCombo.setSelectedItem(mode);
        updatingModeCombo = false;
        timerIntervalSpinner.setEnabled(mode.timer);

        if (mode != previous || !mode.timer) cancelSessionTimer();
        if (mode.timer) {
            if (!isSessionTimerScheduled()) setTimerStatus("starts after the next login run", null);
        } else {
            setTimerStatus("", null);
        }
    }

    /** Main area: pipeline list + editors on the left, config tabs on the right */
    private JComponent buildCenter() {
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        split.setResizeWeight(0.65);
        split.setBorder(null);
        split.setLeftComponent(buildPipelinePane());
        split.setRightComponent(buildRightTabs());

        // resizeWeight only shares out spare space: the first layout follows each side's preferred
        // width, so a wide component on the right could push the divider far left. Pin it to 65/35
        // once the pane has a real width.
        split.addComponentListener(new ComponentAdapter() {
            @Override public void componentResized(ComponentEvent e) {
                if (split.getWidth() > 0) {
                    split.setDividerLocation(0.65);
                    split.removeComponentListener(this);
                }
            }
        });
        return split;
    }

    /** Left side: pipeline list above, request/response editors below */
    private JComponent buildPipelinePane() {

        requestListModel = new DefaultListModel<>();
        requestList = new JList<>(requestListModel);
        requestList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        requestList.setCellRenderer(new DefaultListCellRenderer() {
            @Override public Component getListCellRendererComponent(
                    JList<?> list, Object value, int index,
                    boolean isSelected, boolean cellHasFocus) {
                Component c = super.getListCellRendererComponent(
                    list, value, index, isSelected, cellHasFocus);
                if (!isSelected && index == pipelineActiveReqRow && showingRefresh == activeRunIsRefresh) {
                    c.setBackground(new Color(128, 0, 128));
                    c.setForeground(new Color(255, 215, 0));
                }
                return c;
            }
        });
        requestList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                autoSaveRequest(); // keep edits made to the step we're navigating away from
                selectedRequestIndex = requestList.getSelectedIndex();
                loadSelectedRequest();
            }
        });

        JScrollPane listScroll = new JScrollPane(requestList);

        JButton addBtn     = new JButton("Add");
        JButton addTypeBtn = new JButton("⌄");
        JButton removeBtn  = new JButton("Remove");
        JButton upBtn      = new JButton("↑");
        JButton downBtn    = new JButton("↓");
        JButton saveReqBtn = new JButton("Save Request");

        addBtn.setMargin(new Insets(2, 8, 2, 8));
        addTypeBtn.setMargin(new Insets(2, 4, 2, 4));
        addTypeBtn.setFocusPainted(false);
        addTypeBtn.setToolTipText("Add other step types");
        addStepTypeBtn = addTypeBtn;

        addBtn.addActionListener(e -> addNewRequest());
        addTypeBtn.addActionListener(e -> {
            JPopupMenu menu = new JPopupMenu();
            JMenuItem checkpointItem = new JMenuItem("Checkpoint (manual pause)");
            checkpointItem.addActionListener(ev -> addNewCheckpointStep());
            menu.add(checkpointItem);
            menu.show(addTypeBtn, 0, addTypeBtn.getHeight());
        });
        removeBtn.addActionListener(e -> removeSelectedRequest());
        upBtn.addActionListener(e -> moveRequest(-1));
        downBtn.addActionListener(e -> moveRequest(1));
        saveReqBtn.addActionListener(e -> autoSaveRequest());

        JPanel addSplit = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        addSplit.add(addBtn);
        addSplit.add(addTypeBtn);

        JPanel listBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        listBtns.add(addSplit); listBtns.add(removeBtn);
        listBtns.add(upBtn);  listBtns.add(downBtn);
        listBtns.add(saveReqBtn);

        JPanel listPanel = new JPanel(new BorderLayout(0, 2));
        listPanel.setBorder(BorderFactory.createTitledBorder("Pipeline"));
        listPanel.add(buildPipelineSwitcher(), BorderLayout.NORTH);
        listPanel.add(listScroll, BorderLayout.CENTER);
        listPanel.add(listBtns,  BorderLayout.SOUTH);
        listPanel.setPreferredSize(new Dimension(0, 190));


        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder("Request"));
        requestPanel.add(rawRequestEditor.uiComponent(), BorderLayout.CENTER);

        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(BorderFactory.createTitledBorder("Response"));
        responsePanel.add(rawResponseEditor.uiComponent(), BorderLayout.CENTER);

        JSplitPane editorSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        editorSplit.setResizeWeight(0.5);
        editorSplit.setBorder(null);
        editorSplit.setTopComponent(requestPanel);
        editorSplit.setBottomComponent(responsePanel);


        stepDetailLayout = new CardLayout();
        stepDetailContainer = new JPanel(stepDetailLayout);
        stepDetailContainer.add(editorSplit, "HTTP");
        stepDetailContainer.add(buildCheckpointPanel(), "CHECKPOINT");


        JSplitPane left = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        left.setResizeWeight(0.22);
        left.setBorder(null);
        left.setTopComponent(listPanel);
        left.setBottomComponent(stepDetailContainer);
        return left;
    }

    /** Row above the step list: switches the list between the Login and Refresh pipelines.
     *  Refresh stays locked until the Login pipeline has a refresh token extraction. */
    private JPanel buildPipelineSwitcher() {
        loginViewBtn = new JToggleButton("Login", true);
        refreshViewBtn = new JToggleButton("Refresh 🔒");
        for (JToggleButton b : new JToggleButton[]{loginViewBtn, refreshViewBtn}) {
            b.setMargin(new Insets(2, 10, 2, 10));
            b.setFocusPainted(false);
        }
        refreshViewBtn.setEnabled(false);
        refreshViewBtn.setToolTipText("Add a Refresh Token Extraction to a Login step to unlock");
        loginViewBtn.addActionListener(e -> showPipeline(false));
        refreshViewBtn.addActionListener(e -> showPipeline(true));

        JPanel views = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        views.add(loginViewBtn);
        views.add(refreshViewBtn);

        refreshNowBtn = new JButton("Refresh now");
        refreshNowBtn.setMargin(new Insets(2, 8, 2, 8));
        refreshNowBtn.setFocusPainted(false);
        refreshNowBtn.addActionListener(e -> refreshNow());

        refreshControls = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        refreshControls.add(refreshNowBtn);
        refreshControls.setVisible(false);

        JPanel row = new JPanel(new BorderLayout());
        row.add(views, BorderLayout.WEST);
        row.add(refreshControls, BorderLayout.EAST);
        return row;
    }

    private List<PipelineRequest> shownPipeline() {
        return showingRefresh ? refreshPipeline : pipeline;
    }

    /** Points the step list (and with it the editors and Extractions tab) at the Login or Refresh pipeline. */
    private void showPipeline(boolean refresh) {
        if (refresh && !hasRefreshTokenExtraction()) refresh = false;

        autoSaveRequest();
        showingRefresh = refresh;
        loginViewBtn.setSelected(!refresh);
        refreshViewBtn.setSelected(refresh);
        refreshControls.setVisible(refresh);
        addStepTypeBtn.setEnabled(!refresh); // checkpoints need a human, the Refresh pipeline runs unattended

        requestListModel.clear();
        for (PipelineRequest req : shownPipeline()) {
            requestListModel.addElement(req);
        }
        if (requestListModel.getSize() > 0) {
            requestList.setSelectedIndex(0);
        }
        loadSelectedRequest();
    }

    private boolean hasRefreshTokenExtraction() {
        for (PipelineRequest req : pipeline) {
            if (req.refreshTokenExtraction != null) return true;
        }
        return false;
    }

    /** Locks/unlocks the Refresh pipeline to match whether the Login pipeline extracts a refresh token. */
    private void updateRefreshLock() {
        boolean unlocked = hasRefreshTokenExtraction();
        refreshViewBtn.setEnabled(unlocked);
        refreshViewBtn.setText(unlocked ? "Refresh" : "Refresh 🔒");
        refreshViewBtn.setToolTipText(unlocked
            ? "Pipeline that exchanges each user's refresh token for fresh values"
            : "Add a Refresh Token Extraction to a Login step to unlock");
        if (!unlocked) {
            if (showingRefresh) showPipeline(false);
            if (sessionMode == SessionMode.REFRESH_TIMER) setSessionMode(SessionMode.OFF);
        }
    }

    /** Center panel shown for Checkpoint steps: grayed out unless the pipeline is paused on it */
    private JPanel buildCheckpointPanel() {
        JPanel wrapper = new JPanel(new BorderLayout(0, 0));
        wrapper.setBorder(BorderFactory.createTitledBorder(
            "Checkpoint — pipeline pauses here until you press Continue"));

        checkpointVarsList = new JPanel();
        checkpointVarsList.setLayout(new BoxLayout(checkpointVarsList, BoxLayout.Y_AXIS));
        checkpointVarsList.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
        JScrollPane varsScroll = new JScrollPane(checkpointVarsList);
        varsScroll.setBorder(null);

        addCheckpointVarBtn = new JButton("+ Add Variable");
        addCheckpointVarBtn.setFocusPainted(false);
        addCheckpointVarBtn.addActionListener(e -> addCheckpointVariable());

        JLabel varsHint = new JLabel("  Define variables now; their values are entered while the pipeline is paused here.");
        varsHint.setFont(varsHint.getFont().deriveFont(Font.ITALIC, 11f));
        varsHint.setForeground(UIManager.getColor("Label.disabledForeground"));

        JPanel topBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 4));
        topBar.add(addCheckpointVarBtn);
        topBar.add(varsHint);

        checkpointStatusLabel = new JLabel("Not running.");
        checkpointStatusLabel.setFont(checkpointStatusLabel.getFont().deriveFont(Font.ITALIC, 11f));
        checkpointStatusLabel.setForeground(UIManager.getColor("Label.disabledForeground"));

        checkpointContinueBtn = new JButton("Continue ▶");
        checkpointContinueBtn.setFont(checkpointContinueBtn.getFont().deriveFont(Font.BOLD, 13f));
        checkpointContinueBtn.setFocusPainted(false);
        checkpointContinueBtn.setEnabled(false);
        checkpointContinueBtn.addActionListener(e -> submitCheckpoint());

        JPanel bottomBar = new JPanel(new BorderLayout());
        bottomBar.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));
        bottomBar.add(checkpointStatusLabel, BorderLayout.WEST);
        bottomBar.add(checkpointContinueBtn, BorderLayout.EAST);

        JPanel center = new JPanel(new BorderLayout());
        center.add(topBar, BorderLayout.NORTH);
        center.add(varsScroll, BorderLayout.CENTER);

        wrapper.add(center, BorderLayout.CENTER);
        wrapper.add(bottomBar, BorderLayout.SOUTH);
        return wrapper;
    }

    /** One row in the Checkpoint panel: variable name (fixed) + value input (only live while paused here) */
    private JPanel createCheckpointVarUI(CheckpointVariable var, PipelineRequest owner) {
        JPanel row = new JPanel(new BorderLayout(6, 0));
        row.setBorder(BorderFactory.createEmptyBorder(3, 0, 3, 0));
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        row.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel nameLbl = new JLabel(var.name + ":");
        nameLbl.setPreferredSize(new Dimension(140, 22));
        nameLbl.setFont(nameLbl.getFont().deriveFont(Font.BOLD));

        JTextField valueField = new JTextField();
        valueField.setEnabled(false);
        valueField.addActionListener(e -> submitCheckpoint());
        checkpointValueFields.put(var.name, valueField);

        JButton removeBtn = new JButton("✕");
        removeBtn.setMargin(new Insets(0, 6, 0, 6));
        removeBtn.setFocusPainted(false);
        removeBtn.addActionListener(e -> removeCheckpointVariable(owner, var, row));

        row.add(nameLbl, BorderLayout.WEST);
        row.add(valueField, BorderLayout.CENTER);
        row.add(removeBtn, BorderLayout.EAST);
        return row;
    }

    /** Right side: tabbed pane — Credentials, Static Vars, Extractions, Settings */
    private JTabbedPane buildRightTabs() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Credentials",    buildCredentialsTab());
        tabs.addTab("Static Vars",    buildStaticVarsTab());
        tabs.addTab("Extractions",    buildExtractionsTab());
        tabs.addTab("Patterns",       buildPatternsTab());
        tabs.addTab("Settings",       buildSettingsTab());
        return tabs;
    }

    private JPanel buildCredentialsTab() {
        JPanel panel = new JPanel(new BorderLayout(0, 4));
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        credentialsTableModel = new DefaultTableModel(new String[]{"Username", "Password"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return true; }
        };
        credentialsTable = new JTable(credentialsTableModel) {
            @Override public Component prepareRenderer(TableCellRenderer r, int row, int col) {
                Component c = super.prepareRenderer(r, row, col);
                if (!isRowSelected(row) && row == pipelineActiveCredRow) {
                    c.setBackground(new Color(128, 0, 128));
                    c.setForeground(new Color(255, 215, 0));
                } else if (!isRowSelected(row)) {
                    c.setBackground(getBackground());
                    c.setForeground(getForeground());
                }
                return c;
            }
        };
        credentialsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        credentialsTable.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);

        JButton addBtn   = new JButton("Add");
        JButton removeBtn = new JButton("Remove");
        JButton clearBtn = new JButton("Clear");
        JButton loadBtn  = new JButton("Load file…");
        JButton pasteBtn = new JButton("Paste");

        addBtn.addActionListener(e -> credentialsTableModel.addRow(new Object[]{"", ""}));
        removeBtn.addActionListener(e -> {
            int[] rows = credentialsTable.getSelectedRows();
            for (int i = rows.length - 1; i >= 0; i--) credentialsTableModel.removeRow(rows[i]);
        });
        clearBtn.addActionListener(e -> credentialsTableModel.setRowCount(0));
        loadBtn.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            if (fc.showOpenDialog(panel) == JFileChooser.APPROVE_OPTION) {
                try (java.util.Scanner sc = new java.util.Scanner(fc.getSelectedFile())) {
                    while (sc.hasNextLine()) {
                        String line = sc.nextLine().trim();
                        if (!line.isEmpty() && line.contains(":")) {
                            String[] parts = line.split(":", 2);
                            credentialsTableModel.addRow(new Object[]{parts[0].trim(), parts[1].trim()});
                        }
                    }
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(panel, "Error loading file: " + ex.getMessage());
                }
            }
        });
        pasteBtn.addActionListener(e -> {
            try {
                String clip = (String) Toolkit.getDefaultToolkit()
                    .getSystemClipboard().getData(java.awt.datatransfer.DataFlavor.stringFlavor);
                for (String line : clip.split("\n")) {
                    line = line.trim();
                    if (!line.isEmpty() && line.contains(":")) {
                        String[] parts = line.split(":", 2);
                        credentialsTableModel.addRow(new Object[]{parts[0].trim(), parts[1].trim()});
                    }
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "Error pasting: " + ex.getMessage());
            }
        });

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        btns.add(addBtn); btns.add(removeBtn); btns.add(clearBtn);
        btns.add(loadBtn); btns.add(pasteBtn);

        panel.add(new JScrollPane(credentialsTable), BorderLayout.CENTER);
        panel.add(btns, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel buildStaticVarsTab() {
        JPanel panel = new JPanel(new BorderLayout(0, 4));
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        staticVarsTableModel = new DefaultTableModel(new String[]{"Variable Name", "Value"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return true; }
        };
        staticVarsTable = new JTable(staticVarsTableModel);
        staticVarsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        staticVarsTable.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);
        staticVarsTableModel.addTableModelListener(e -> updateAvailableVariables());

        JButton addBtn    = new JButton("Add");
        JButton removeBtn = new JButton("Remove");
        JButton clearBtn  = new JButton("Clear");
        addBtn.addActionListener(e -> staticVarsTableModel.addRow(new Object[]{"", ""}));
        removeBtn.addActionListener(e -> {
            int[] rows = staticVarsTable.getSelectedRows();
            for (int i = rows.length - 1; i >= 0; i--) staticVarsTableModel.removeRow(rows[i]);
        });
        clearBtn.addActionListener(e -> staticVarsTableModel.setRowCount(0));

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        btns.add(addBtn); btns.add(removeBtn); btns.add(clearBtn);

        panel.add(new JScrollPane(staticVarsTable), BorderLayout.CENTER);
        panel.add(btns, BorderLayout.SOUTH);
        return panel;
    }

    /** Extractions tab — shows extractions for the selected pipeline request */
    private JPanel buildExtractionsTab() {
        JPanel wrapper = new JPanel(new BorderLayout(0, 4));
        wrapper.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        extractionPanel = new JPanel();
        extractionPanel.setLayout(new BoxLayout(extractionPanel, BoxLayout.Y_AXIS));
        JScrollPane scroll = new JScrollPane(extractionPanel);

        JButton addExtBtn  = new JButton("Add Extraction");
        JButton addAuthBtn = new JButton("Add Auth Extraction ⭐");
        addExtBtn.setFocusPainted(false);
        addAuthBtn.setFocusPainted(false);
        addExtBtn.addActionListener(e -> addExtraction());
        addAuthBtn.addActionListener(e -> addAuthExtraction());

        JLabel hint = new JLabel(" Select a request from the pipeline first.");
        hint.setFont(hint.getFont().deriveFont(Font.ITALIC, 11f));
        hint.setForeground(UIManager.getColor("Label.disabledForeground"));

        JButton addRefreshBtn = new JButton("Add Refresh Token Extraction 🔄");
        addRefreshBtn.setFocusPainted(false);
        addRefreshBtn.addActionListener(e -> addRefreshTokenExtraction());

        JPanel plainRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        plainRow.add(addExtBtn); plainRow.add(hint);
        JPanel specialRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        specialRow.add(addAuthBtn); specialRow.add(addRefreshBtn);

        JPanel btns = new JPanel(new GridLayout(2, 1, 0, 4));
        btns.add(plainRow); btns.add(specialRow);

        wrapper.add(btns,   BorderLayout.NORTH);
        wrapper.add(scroll, BorderLayout.CENTER);
        return wrapper;
    }

    /** Patterns tab — read-only reference of available pattern tokens */
    private JPanel buildPatternsTab() {
        JPanel panel = new JPanel(new BorderLayout(0, 4));
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        availableVarsArea = new JTextArea();
        availableVarsArea.setEditable(false);
        availableVarsArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        panel.add(new JScrollPane(availableVarsArea), BorderLayout.CENTER);
        return panel;
    }

    /** Settings tab — expiration strings + HTTP config in one clean place */
    private JPanel buildSettingsTab() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));


        JPanel httpSection = new JPanel();
        httpSection.setLayout(new BoxLayout(httpSection, BoxLayout.Y_AXIS));
        httpSection.setBorder(BorderFactory.createTitledBorder("HTTP Service Defaults"));
        httpSection.setAlignmentX(Component.LEFT_ALIGNMENT);
        httpSection.setMaximumSize(new Dimension(Integer.MAX_VALUE, 130));

        JPanel portRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        portRow.add(new JLabel("Default Port:"));
        defaultPortField = new JTextField("443", 7);
        defaultPortField.setFont(new Font("Monospaced", Font.PLAIN, 12));
        defaultPortField.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) { updatePort(); }
            public void removeUpdate(DocumentEvent e)  { updatePort(); }
            public void insertUpdate(DocumentEvent e)  { updatePort(); }
        });
        portRow.add(defaultPortField);

        forceHttpsCheckbox = new JCheckBox("Force HTTPS", true);
        forceHttpsCheckbox.addActionListener(e -> {
            configuredHttps = forceHttpsCheckbox.isSelected();
            if (configuredHttps && configuredPort == 80) defaultPortField.setText("443");
            else if (!configuredHttps && configuredPort == 443) defaultPortField.setText("80");
        });

        JLabel httpNote = new JLabel("  ⚠ Applied to all pipeline requests");
        httpNote.setFont(httpNote.getFont().deriveFont(10f));
        httpNote.setForeground(new Color(200, 100, 0));

        httpSection.add(portRow);
        JPanel httpsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        httpsRow.add(forceHttpsCheckbox);
        httpsRow.add(httpNote);
        httpSection.add(httpsRow);


        JPanel expSection = new JPanel(new BorderLayout(0, 4));
        expSection.setBorder(BorderFactory.createTitledBorder("Session Expiration Strings (one per line)"));
        expSection.setAlignmentX(Component.LEFT_ALIGNMENT);

        expirationStringsArea = new JTextArea(5, 20);
        expirationStringsArea.setLineWrap(true);
        expirationStringsArea.setFont(new Font("Monospaced", Font.PLAIN, 11));

        JButton addExpBtn   = new JButton("Add");
        JButton pasteExpBtn = new JButton("Paste");
        JButton clearExpBtn = new JButton("Clear");

        addExpBtn.addActionListener(e -> {
            String val = JOptionPane.showInputDialog(mainPanel, "Enter expiration string:");
            if (val != null && !val.trim().isEmpty()) {
                String cur = expirationStringsArea.getText();
                if (!cur.isEmpty() && !cur.endsWith("\n")) cur += "\n";
                expirationStringsArea.setText(cur + val.trim());
                updateExpirationStringsList();
            }
        });
        pasteExpBtn.addActionListener(e -> {
            try {
                String clip = (String) Toolkit.getDefaultToolkit()
                    .getSystemClipboard().getData(java.awt.datatransfer.DataFlavor.stringFlavor);
                String cur = expirationStringsArea.getText();
                if (!cur.isEmpty() && !cur.endsWith("\n")) cur += "\n";
                expirationStringsArea.setText(cur + clip);
                updateExpirationStringsList();
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(mainPanel, "Error pasting: " + ex.getMessage());
            }
        });
        clearExpBtn.addActionListener(e -> { expirationStringsArea.setText(""); updateExpirationStringsList(); });

        expirationStringsArea.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) { updateExpirationStringsList(); }
            public void removeUpdate(DocumentEvent e)  { updateExpirationStringsList(); }
            public void insertUpdate(DocumentEvent e)  { updateExpirationStringsList(); }
        });

        JPanel expBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        expBtns.add(addExpBtn); expBtns.add(pasteExpBtn); expBtns.add(clearExpBtn);

        expSection.add(new JScrollPane(expirationStringsArea), BorderLayout.CENTER);
        expSection.add(expBtns, BorderLayout.SOUTH);


        JPanel autoAuthSection = new JPanel(new BorderLayout(0, 4));
        autoAuthSection.setBorder(BorderFactory.createTitledBorder(
                "Auto-Authorization Headers (triggered by \"" + AUTO_AUTH_TRIGGER_HEADER + ": <username>\")"));
        autoAuthSection.setAlignmentX(Component.LEFT_ALIGNMENT);

        autoAuthHeadersTableModel = new DefaultTableModel(new String[]{"Header Name", "Header Value"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return true; }
        };
        autoAuthHeadersTable = new JTable(autoAuthHeadersTableModel);
        autoAuthHeadersTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        autoAuthHeadersTable.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);

        JScrollPane autoAuthScroll = new JScrollPane(autoAuthHeadersTable);
        autoAuthScroll.setPreferredSize(new Dimension(0, 100));

        JButton addAutoAuthBtn    = new JButton("Add");
        JButton removeAutoAuthBtn = new JButton("Remove");
        JButton clearAutoAuthBtn  = new JButton("Clear");
        addAutoAuthBtn.addActionListener(e -> autoAuthHeadersTableModel.addRow(new Object[]{"", ""}));
        removeAutoAuthBtn.addActionListener(e -> {
            int[] rows = autoAuthHeadersTable.getSelectedRows();
            for (int i = rows.length - 1; i >= 0; i--) autoAuthHeadersTableModel.removeRow(rows[i]);
        });
        clearAutoAuthBtn.addActionListener(e -> autoAuthHeadersTableModel.setRowCount(0));

        JPanel autoAuthBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        autoAuthBtns.add(addAutoAuthBtn); autoAuthBtns.add(removeAutoAuthBtn); autoAuthBtns.add(clearAutoAuthBtn);

        JPanel autoAuthSouth = new JPanel(new BorderLayout());
        autoAuthSouth.add(autoAuthBtns, BorderLayout.NORTH);

        autoAuthSection.add(autoAuthScroll, BorderLayout.CENTER);
        autoAuthSection.add(autoAuthSouth, BorderLayout.SOUTH);

        panel.add(httpSection);
        panel.add(Box.createVerticalStrut(12));
        panel.add(expSection);
        panel.add(Box.createVerticalStrut(12));
        panel.add(autoAuthSection);
        return panel;
    }

    /** True if COOOKIES holds session values for this user (i.e. it has been through the login pipeline). */
    private boolean hasSession(String username) {
        return !username.isEmpty()
            && (finalAuthValues.containsKey(username) || extractedValues.containsKey(username));
    }

    /** Points an Auto-Authorization rule's USERNAME placeholders at the requested user, so that
     *  <__COOOKIES__:USERNAME> and <COOOKIES:USERNAME:var> then resolve like any other pattern. */
    private String bindAutoAuthUser(String template, String username) {
        return template
            .replace("<__COOOKIES__:USERNAME>", "<__COOOKIES__:" + username + ">")
            .replace("<COOOKIES:USERNAME:", "<COOOKIES:" + username + ":");
    }

    /** Reads the user-configured Auto-Authorization headers from the Settings tab table. */
    private List<String[]> getConfiguredAutoAuthHeaders() {
        List<String[]> headers = new ArrayList<>();
        if (autoAuthHeadersTableModel == null) return headers;

        for (int i = 0; i < autoAuthHeadersTableModel.getRowCount(); i++) {
            String name  = (String) autoAuthHeadersTableModel.getValueAt(i, 0);
            String value = (String) autoAuthHeadersTableModel.getValueAt(i, 1);
            if (name != null && !name.trim().isEmpty() && value != null) {
                headers.add(new String[]{name.trim(), value});
            }
        }

        api.logging().logToOutput("[COOOKIES] Auto-Auth table has " + autoAuthHeadersTableModel.getRowCount() +
                " row(s); " + headers.size() + " valid header(s) read: " +
                headers.stream().map(h -> h[0]).reduce((a, b) -> a + ", " + b).orElse("(none)"));

        return headers;
    }

    /**
     * Rebuilds the raw request text: strips the internal trigger header plus any existing
     * occurrence of each configured header, then appends the configured headers fresh.
     * Done as a plain string rewrite (same approach the pattern-replacement code already
     * uses) because chaining withRemovedHeader/withUpdatedHeader directly on the
     * HttpRequestToBeSent object the handler receives does not reliably stick.
     */
    private String applyAutoAuthHeaders(String rawRequest, List<String[]> headers) {
        int bodyIdx = rawRequest.indexOf("\r\n\r\n");
        String headPart = (bodyIdx == -1) ? rawRequest : rawRequest.substring(0, bodyIdx);
        String bodyPart = (bodyIdx == -1) ? "" : rawRequest.substring(bodyIdx);

        Set<String> namesToStrip = new HashSet<>();
        namesToStrip.add(AUTO_AUTH_TRIGGER_HEADER.toLowerCase());
        for (String[] h : headers) namesToStrip.add(h[0].trim().toLowerCase());

        String[] lines = headPart.split("\r\n", -1);
        StringBuilder newHead = new StringBuilder();
        newHead.append(lines.length > 0 ? lines[0] : ""); // request line, unchanged

        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            int colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                String headerName = line.substring(0, colonIdx).trim().toLowerCase();
                if (namesToStrip.contains(headerName)) continue; // drop; re-added fresh below if configured
            }
            newHead.append("\r\n").append(line);
        }

        for (String[] h : headers) {
            newHead.append("\r\n").append(h[0].trim()).append(": ").append(h[1]);
        }

        return newHead.toString() + bodyPart;
    }

    /** Collapsible log drawer at the bottom (like TheAlchemist's API reference) */
    private JPanel buildLogDrawer() {
        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setOpaque(false);

        JLabel toggleLbl = new JLabel("▲  Execution Log");
        toggleLbl.setFont(toggleLbl.getFont().deriveFont(Font.BOLD, 11f));
        toggleLbl.setForeground(UIManager.getColor("Label.disabledForeground"));
        toggleLbl.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        toggleLbl.setBorder(BorderFactory.createEmptyBorder(5, 14, 5, 14));

        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 11));

        JPanel logContent = new JPanel(new BorderLayout());
        logContent.setBorder(BorderFactory.createEmptyBorder(0, 14, 8, 14));

        JScrollPane logScroll = new JScrollPane(logArea);
        logScroll.setPreferredSize(new Dimension(0, 160));

        JButton clearLogBtn = new JButton("Clear");
        clearLogBtn.setFont(clearLogBtn.getFont().deriveFont(10f));
        clearLogBtn.setFocusPainted(false);
        clearLogBtn.addActionListener(e -> logArea.setText(""));

        JPanel logBtns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 2));
        logBtns.setOpaque(false);
        logBtns.add(clearLogBtn);

        logContent.add(logBtns,   BorderLayout.NORTH);
        logContent.add(logScroll, BorderLayout.CENTER);
        logContent.setVisible(false);

        toggleLbl.addMouseListener(new MouseAdapter() {
            boolean visible = false;
            @Override public void mouseClicked(MouseEvent e) {
                visible = !visible;
                logContent.setVisible(visible);
                toggleLbl.setText((visible ? "▼" : "▲") + "  Execution Log");
                wrapper.revalidate();
            }
        });

        statusLabel = new JLabel("Ready");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD, 11f));
        statusLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
        statusLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 14));

        JPanel headerBar = new JPanel(new BorderLayout());
        headerBar.setOpaque(false);
        headerBar.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0,
            UIManager.getColor("Separator.foreground")));
        headerBar.add(toggleLbl,   BorderLayout.WEST);
        headerBar.add(statusLabel, BorderLayout.EAST);

        wrapper.add(headerBar,  BorderLayout.NORTH);
        wrapper.add(logContent, BorderLayout.CENTER);
        return wrapper;
    }


    private void updatePort() {
        try {
            int newPort = Integer.parseInt(defaultPortField.getText().trim());
            if (newPort > 0 && newPort <= 65535) configuredPort = newPort;
        } catch (NumberFormatException e) {

        }
    }

    private void addNewRequest() {
        String name = JOptionPane.showInputDialog(mainPanel, "Enter request name:");
        if (name != null && !name.trim().isEmpty()) {
            PipelineRequest req = new PipelineRequest(name.trim());
            req.rawRequest = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
            shownPipeline().add(req);
            requestListModel.addElement(req);
            requestList.setSelectedIndex(requestListModel.getSize() - 1);
        }
    }

    /** Steps can't be removed, reordered or replaced mid-run: the worker walks the pipeline by index
     *  and may be parked on a checkpoint step. */
    private boolean blockedByRunningPipeline() {
        if (!pipelineRunning.get()) return false;
        JOptionPane.showMessageDialog(mainPanel,
            "The pipeline is running. Wait for it to finish first.",
            "Pipeline Running", JOptionPane.WARNING_MESSAGE);
        return true;
    }

    private void removeSelectedRequest() {
        int idx = requestList.getSelectedIndex();
        if (idx >= 0) {
            if (blockedByRunningPipeline()) return;
            shownPipeline().remove(idx);
            requestListModel.remove(idx);
            if (requestListModel.getSize() > 0) {
                requestList.setSelectedIndex(Math.min(idx, requestListModel.getSize() - 1));
            } else {
                loadSelectedRequest();
            }
            updateRefreshLock();
        }
    }

    private void moveRequest(int direction) {
        int idx = requestList.getSelectedIndex();
        if (idx < 0) return;

        int newIdx = idx + direction;
        if (newIdx < 0 || newIdx >= requestListModel.getSize()) return;
        if (blockedByRunningPipeline()) return;

        PipelineRequest req = shownPipeline().remove(idx);
        shownPipeline().add(newIdx, req);

        requestListModel.remove(idx);
        requestListModel.add(newIdx, req);
        requestList.setSelectedIndex(newIdx);
    }

    private void loadSelectedRequest() {
        int idx = requestList.getSelectedIndex();
        List<PipelineRequest> steps = shownPipeline();
        editorOwner = null;

        if (idx < 0 || idx >= steps.size()) {
            clearStepDetail();
            return;
        }

        PipelineRequest req = steps.get(idx);
        editorOwner = req;

        if (req.stepType == PipelineRequest.TYPE_CHECKPOINT) {
            showCheckpointStep(req, idx);
            return;
        }

        stepDetailLayout.show(stepDetailContainer, "HTTP");
        rawRequestEditor.setRequest(HttpRequest.httpRequest(req.rawRequest));

        if (req.lastResponse != null && !req.lastResponse.isEmpty()) {
            rawResponseEditor.setResponse(HttpResponse.httpResponse(req.lastResponse));
        } else {
            rawResponseEditor.setResponse(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n"));
        }

        rebuildExtractionPanel(req);
        updateAvailableVariables();
    }

    /** Resets the editors, Extractions tab and Checkpoint panel when no step is selected. */
    private void clearStepDetail() {
        stepDetailLayout.show(stepDetailContainer, "HTTP");
        clearEditorsForImport();
        extractionPanel.removeAll();
        extractionPanel.revalidate();
        extractionPanel.repaint();
        checkpointVarsList.removeAll();
        checkpointValueFields.clear();
        setCheckpointInteractable(false);
        checkpointVarsList.revalidate();
        checkpointVarsList.repaint();
        updateAvailableVariables();
    }

    private void rebuildExtractionPanel(PipelineRequest req) {
        extractionPanel.removeAll();
        if (req.authExtraction != null) {
            extractionPanel.add(createAuthExtractionUI(req.authExtraction, false));
        }
        if (req.refreshTokenExtraction != null) {
            extractionPanel.add(createAuthExtractionUI(req.refreshTokenExtraction, true));
        }
        for (Extraction ext : req.extractions) {
            extractionPanel.add(createExtractionUI(ext));
        }
        extractionPanel.revalidate();
        extractionPanel.repaint();
    }

    /** Swap the center detail area to the Checkpoint card for this step, rebuild its variable rows,
     *  and enable it only if the pipeline is actually paused on this exact step right now. */
    private void showCheckpointStep(PipelineRequest req, int idx) {
        stepDetailLayout.show(stepDetailContainer, "CHECKPOINT");

        checkpointVarsList.removeAll();
        checkpointValueFields.clear();
        for (CheckpointVariable cv : req.checkpointVariables) {
            checkpointVarsList.add(createCheckpointVarUI(cv, req));
        }
        checkpointVarsList.revalidate();
        checkpointVarsList.repaint();

        boolean live = awaitingCheckpoint && awaitingCheckpointStepIdx == idx;
        setCheckpointInteractable(live);

        extractionPanel.removeAll();
        JLabel note = new JLabel("  Checkpoint steps don't use Extractions — add variables in the main panel.");
        note.setFont(note.getFont().deriveFont(Font.ITALIC, 11f));
        note.setForeground(UIManager.getColor("Label.disabledForeground"));
        extractionPanel.add(note);
        extractionPanel.revalidate();
        extractionPanel.repaint();

        updateAvailableVariables();
    }

    /** Writes the request editor's content back into the step it was loaded from. */
    private void autoSaveRequest() {
        PipelineRequest req = editorOwner;
        if (req == null || (!pipeline.contains(req) && !refreshPipeline.contains(req))) return;
        if (req.stepType == PipelineRequest.TYPE_CHECKPOINT) return; // no HTTP editor content to persist
        HttpRequest request = rawRequestEditor.getRequest();
        if (request != null) {
            req.rawRequest = request.toString();
        }
    }

    private void updateAvailableVariables() {
        int idx = requestList.getSelectedIndex();
        List<PipelineRequest> steps = shownPipeline();

        StringBuilder sb = new StringBuilder();

        sb.append("Always available:\n");
        sb.append("  <COOOKIES:USERNAME>\n");
        sb.append("  <COOOKIES:PASSWORD>\n");
        sb.append("  <COOOKIES:COOKIES>\n\n");

        sb.append("Static variables:\n");
        boolean hasStaticVars = false;
        for (int i = 0; i < staticVarsTableModel.getRowCount(); i++) {
            String varName = (String) staticVarsTableModel.getValueAt(i, 0);
            if (varName != null && !varName.trim().isEmpty()) {
                sb.append("  <COOOKIES:").append(varName.trim()).append(">\n");
                hasStaticVars = true;
            }
        }
        if (!hasStaticVars) {
            sb.append("  (none defined)\n");
        }
        sb.append("\n");

        if (showingRefresh) {
            sb.append("From the login pipeline (this user's current values):\n");
            sb.append("  <COOOKIES:").append(REFRESH_TOKEN_VAR).append(">\n");
            for (PipelineRequest loginReq : pipeline) {
                for (Extraction ext : loginReq.extractions) {
                    sb.append("  <COOOKIES:").append(ext.name).append(">\n");
                }
                for (CheckpointVariable cv : loginReq.checkpointVariables) {
                    sb.append("  <COOOKIES:").append(cv.name).append("> (checkpoint)\n");
                }
            }
            sb.append("\n");
        }

        if (idx < 0) {
            sb.append("From previous requests:\n  (select a request)");
            availableVarsArea.setText(sb.toString());
            return;
        }

        sb.append("From previous requests:\n");
        boolean hasExtracted = false;
        for (int i = 0; i < idx && i < steps.size(); i++) {
            PipelineRequest prevReq = steps.get(i);
            for (Extraction ext : prevReq.extractions) {
                sb.append("  <COOOKIES:").append(ext.name).append(">\n");
                hasExtracted = true;
            }
            for (CheckpointVariable cv : prevReq.checkpointVariables) {
                sb.append("  <COOOKIES:").append(cv.name).append("> (checkpoint)\n");
                hasExtracted = true;
            }
            if (prevReq.refreshTokenExtraction != null) {
                sb.append("  <COOOKIES:").append(REFRESH_TOKEN_VAR).append("> (refresh token)\n");
                hasExtracted = true;
            }
        }

        if (!hasExtracted) {
            sb.append("  (none yet)\n");
        }

        availableVarsArea.setText(sb.toString());
    }

    private void updateExpirationStringsList() {
        synchronized (expirationStrings) {
            expirationStrings.clear();
            String text = expirationStringsArea.getText();
            if (text != null && !text.trim().isEmpty()) {
                String[] lines = text.split("\n");
                for (String line : lines) {
                    String trimmed = line.trim();
                    if (!trimmed.isEmpty()) {
                        expirationStrings.add(trimmed);
                    }
                }
            }
        }
    }

    private void addExtraction() {
        int idx = requestList.getSelectedIndex();
        if (idx < 0) {
            JOptionPane.showMessageDialog(mainPanel, "Please select a request first.");
            return;
        }

        PipelineRequest req = shownPipeline().get(idx);
        if (req.stepType == PipelineRequest.TYPE_CHECKPOINT) {
            JOptionPane.showMessageDialog(mainPanel, "Checkpoint steps don't use Extractions — add variables in the main panel.");
            return;
        }

        String name = JOptionPane.showInputDialog(mainPanel, "Enter unique extraction name:");
        if (name == null || name.trim().isEmpty()) return;

        if (isVariableNameTaken(name.trim())) {
            JOptionPane.showMessageDialog(mainPanel, "Name already exists!");
            return;
        }

        Extraction ext = new Extraction(name.trim());
        req.extractions.add(ext);
        extractionPanel.add(createExtractionUI(ext));
        extractionPanel.revalidate();
        extractionPanel.repaint();
        updateAvailableVariables();
    }

    private void addNewCheckpointStep() {
        if (showingRefresh) return; // the Refresh pipeline runs unattended
        String name = JOptionPane.showInputDialog(mainPanel, "Enter checkpoint step name:");
        if (name != null && !name.trim().isEmpty()) {
            PipelineRequest req = new PipelineRequest(name.trim());
            req.stepType = PipelineRequest.TYPE_CHECKPOINT;
            req.rawRequest = "";
            pipeline.add(req);
            requestListModel.addElement(req);
            requestList.setSelectedIndex(requestListModel.getSize() - 1);
        }
    }

    /** Names are shared between Extractions and Checkpoint Variables across the whole pipeline,
     *  since both ultimately populate the same per-credential variable map. */
    private boolean isVariableNameTaken(String name) {
        if (name.equals("USERNAME") || name.equals("PASSWORD") || name.equals("COOKIES") || name.equals(REFRESH_TOKEN_VAR)) return true;

        for (int i = 0; i < staticVarsTableModel.getRowCount(); i++) {
            String staticName = (String) staticVarsTableModel.getValueAt(i, 0);
            if (staticName != null && staticName.trim().equals(name)) return true;
        }



        for (PipelineRequest r : shownPipeline()) {
            for (Extraction ext : r.extractions) {
                if (ext.name.equals(name)) return true;
            }
            for (CheckpointVariable cv : r.checkpointVariables) {
                if (cv.name.equals(name)) return true;
            }
        }
        return false;
    }

    private void addCheckpointVariable() {
        int idx = requestList.getSelectedIndex();
        if (idx < 0 || idx >= pipeline.size()) return;
        PipelineRequest req = pipeline.get(idx);
        if (req.stepType != PipelineRequest.TYPE_CHECKPOINT) return;

        String name = JOptionPane.showInputDialog(mainPanel, "Enter unique variable name:");
        if (name == null || name.trim().isEmpty()) return;
        name = name.trim();

        if (isVariableNameTaken(name)) {
            JOptionPane.showMessageDialog(mainPanel, "Name already exists!");
            return;
        }

        CheckpointVariable var = new CheckpointVariable(name);
        req.checkpointVariables.add(var);
        checkpointVarsList.add(createCheckpointVarUI(var, req));
        checkpointVarsList.revalidate();
        checkpointVarsList.repaint();
        updateAvailableVariables();
    }

    private void removeCheckpointVariable(PipelineRequest owner, CheckpointVariable var, JPanel row) {
        owner.checkpointVariables.remove(var);
        checkpointValueFields.remove(var.name);
        checkpointVarsList.remove(row);
        checkpointVarsList.revalidate();
        checkpointVarsList.repaint();
        updateAvailableVariables();
    }

    /** Enables/disables the Continue button and all value fields for the currently displayed checkpoint. */
    private void setCheckpointInteractable(boolean live) {
        checkpointContinueBtn.setEnabled(live);
        for (JTextField f : checkpointValueFields.values()) {
            f.setEnabled(live);
        }
        checkpointStatusLabel.setText(live
            ? "⏸ Paused — fill in values (if any) and click Continue."
            : "Not running.");
    }

    /** Called on the EDT when the user clicks Continue. Reads current field values, hands them
     *  off to the paused pipeline thread, and unblocks it — regardless of whether any value was filled in. */
    private void submitCheckpoint() {
        if (!awaitingCheckpoint) return;

        Map<String, String> values = new HashMap<>();
        for (Map.Entry<String, JTextField> e : checkpointValueFields.entrySet()) {
            values.put(e.getKey(), e.getValue().getText());
            e.getValue().setText("");
        }
        pendingCheckpointValues = values;

        setCheckpointInteractable(false);
        checkpointStatusLabel.setText("Continuing…");
        checkpointContinueSignal.offer(Boolean.TRUE);
    }

    private void addAuthExtraction() {
        addSpecialExtraction(false);
    }

    private void addRefreshTokenExtraction() {
        addSpecialExtraction(true);
    }

    /** Adds the pipeline's single Auth extraction or its single Refresh Token extraction to the selected step. */
    private void addSpecialExtraction(boolean refreshToken) {
        int idx = requestList.getSelectedIndex();
        if (idx < 0) {
            JOptionPane.showMessageDialog(mainPanel, "Please select a request first.");
            return;
        }

        String label = refreshToken ? "Refresh token extraction" : "Auth extraction";
        for (PipelineRequest req : shownPipeline()) {
            if ((refreshToken ? req.refreshTokenExtraction : req.authExtraction) != null) {
                JOptionPane.showMessageDialog(mainPanel,
                    label + " already exists in request: " + req.name + "\n" +
                    "Only one allowed per pipeline.",
                    label + " Exists",
                    JOptionPane.WARNING_MESSAGE);
                return;
            }
        }

        PipelineRequest req = shownPipeline().get(idx);
        if (req.stepType == PipelineRequest.TYPE_CHECKPOINT) {
            JOptionPane.showMessageDialog(mainPanel, "Checkpoint steps don't use Extractions — select an HTTP request step.");
            return;
        }

        if (refreshToken) {
            req.refreshTokenExtraction = new AuthExtraction();
        } else {
            req.authExtraction = new AuthExtraction();
        }

        rebuildExtractionPanel(req);
        updateAvailableVariables();
        updateRefreshLock();
    }

    private JPanel createExtractionUI(Extraction ext) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(ext.name));
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 180));

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));

        String[] types = {"Header", "JSON", "Regex"};
        JComboBox<String> typeCombo = new JComboBox<>(types);
        typeCombo.setSelectedIndex(ext.type);

        JTextField valueField = new JTextField(ext.value, 20);
        valueField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 25));

        JTextArea exampleArea = new JTextArea(3, 20);
        exampleArea.setEditable(false);
        exampleArea.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        updateExampleText(exampleArea, ext.type);

        JButton removeBtn  = new JButton("Remove");
        JButton helpMeBtn  = new JButton("Regex Builder (for the weak)");
        helpMeBtn.setFont(helpMeBtn.getFont().deriveFont(Font.BOLD, 11f));
        helpMeBtn.setForeground(new Color(60, 120, 220));
        helpMeBtn.setFocusPainted(false);
        helpMeBtn.setVisible(ext.type == 2);

        typeCombo.addActionListener(e -> {
            ext.type = typeCombo.getSelectedIndex();
            updateExampleText(exampleArea, ext.type);
            helpMeBtn.setVisible(ext.type == 2);
            panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, ext.type == 2 ? 210 : 180));
            panel.revalidate();
        });

        valueField.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) { ext.value = valueField.getText(); }
            public void removeUpdate(DocumentEvent e)  { ext.value = valueField.getText(); }
            public void insertUpdate(DocumentEvent e)  { ext.value = valueField.getText(); }
        });

        removeBtn.addActionListener(e -> {
            int idx = requestList.getSelectedIndex();
            if (idx >= 0) {
                shownPipeline().get(idx).extractions.remove(ext);
                extractionPanel.remove(panel);
                extractionPanel.revalidate();
                extractionPanel.repaint();
                updateAvailableVariables();
            }
        });

        helpMeBtn.addActionListener(e -> {
            String lastResponse = "";
            int idx = requestList.getSelectedIndex();
            if (idx >= 0 && idx < shownPipeline().size()) lastResponse = shownPipeline().get(idx).lastResponse;
            showRegexHelper(valueField, lastResponse != null ? lastResponse : "");
        });

        JPanel typePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        typePanel.add(new JLabel("Type: "));
        typePanel.add(typeCombo);

        JPanel valuePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        valuePanel.add(new JLabel("Value: "));
        valuePanel.add(valueField);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        btnPanel.add(removeBtn);
        btnPanel.add(helpMeBtn);

        content.add(typePanel);
        content.add(valuePanel);
        content.add(new JLabel("Example:"));
        content.add(exampleArea);
        content.add(btnPanel);

        panel.add(content);
        return panel;
    }

    /** Panel for a pipeline's Final Auth Value extraction, or (refreshToken) its Refresh Token extraction. */
    private JPanel createAuthExtractionUI(AuthExtraction authExt, boolean refreshToken) {
        JPanel panel = new JPanel(new BorderLayout());
        Color accent = refreshToken ? new Color(46, 139, 87) : new Color(70, 130, 180);

        TitledBorder border = BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(accent, 2),
            refreshToken ? "🔄 REFRESH TOKEN" : "⭐ FINAL AUTH VALUE",
            TitledBorder.LEFT,
            TitledBorder.TOP,
            new Font("Dialog", Font.BOLD, 12),
            accent
        );
        panel.setBorder(border);
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 180));

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));

        String[] types = {"Header", "JSON", "Regex"};
        JComboBox<String> typeCombo = new JComboBox<>(types);
        typeCombo.setSelectedIndex(authExt.type);

        JTextField valueField = new JTextField(authExt.value, 20);
        valueField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 25));

        JTextArea exampleArea = new JTextArea(3, 20);
        exampleArea.setEditable(false);
        exampleArea.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        updateExampleText(exampleArea, authExt.type);

        JButton removeBtn = new JButton("Remove");
        JButton helpMeBtn = new JButton("Regex Builder (for the weak)");
        helpMeBtn.setFont(helpMeBtn.getFont().deriveFont(Font.BOLD, 11f));
        helpMeBtn.setForeground(new Color(60, 120, 220));
        helpMeBtn.setFocusPainted(false);
        helpMeBtn.setVisible(authExt.type == 2);

        typeCombo.addActionListener(e -> {
            authExt.type = typeCombo.getSelectedIndex();
            updateExampleText(exampleArea, authExt.type);
            helpMeBtn.setVisible(authExt.type == 2);
            panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, authExt.type == 2 ? 210 : 180));
            panel.revalidate();
        });

        valueField.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) { authExt.value = valueField.getText(); }
            public void removeUpdate(DocumentEvent e)  { authExt.value = valueField.getText(); }
            public void insertUpdate(DocumentEvent e)  { authExt.value = valueField.getText(); }
        });

        removeBtn.addActionListener(e -> {
            int idx = requestList.getSelectedIndex();
            if (idx >= 0) {
                PipelineRequest owner = shownPipeline().get(idx);
                if (refreshToken) {
                    owner.refreshTokenExtraction = null;
                } else {
                    owner.authExtraction = null;
                }
                extractionPanel.remove(panel);
                extractionPanel.revalidate();
                extractionPanel.repaint();
                updateAvailableVariables();
                updateRefreshLock();
            }
        });

        helpMeBtn.addActionListener(e -> {
            String lastResponse = "";
            int idx = requestList.getSelectedIndex();
            if (idx >= 0 && idx < shownPipeline().size()) lastResponse = shownPipeline().get(idx).lastResponse;
            showRegexHelper(valueField, lastResponse != null ? lastResponse : "");
        });

        JPanel typePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        typePanel.add(new JLabel("Type: "));
        typePanel.add(typeCombo);

        JPanel valuePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        valuePanel.add(new JLabel("Value: "));
        valuePanel.add(valueField);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        btnPanel.add(removeBtn);
        btnPanel.add(helpMeBtn);

        String storedAs = refreshToken ? "<COOOKIES:" + REFRESH_TOKEN_VAR + ">" : "<__COOOKIES__:USERNAME>";
        JLabel infoLabel = new JLabel(showingRefresh
            ? "Overwrites " + storedAs + " after every refresh"
            : "Stored as: " + storedAs + (refreshToken ? " — unlocks the Refresh pipeline" : ""));
        infoLabel.setFont(new Font("Dialog", Font.PLAIN, 10));
        infoLabel.setForeground(accent);

        content.add(typePanel);
        content.add(valuePanel);
        content.add(new JLabel("Example:"));
        content.add(exampleArea);
        content.add(btnPanel);
        content.add(Box.createVerticalStrut(5));
        content.add(infoLabel);

        panel.add(content);
        return panel;
    }


    private void showRegexHelper(JTextField targetValueField, String initialResponse) {
        JFrame ownerFrame = new JFrame();
        ownerFrame.setUndecorated(true);
        ownerFrame.setVisible(true);
        ownerFrame.setLocation(-1, -1);
        ownerFrame.setSize(0, 0);

        JDialog dialog = new JDialog(ownerFrame,
            "Regex Builder", java.awt.Dialog.ModalityType.MODELESS);
        dialog.setSize(800, 600);
        dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE); // so the window's X also fires windowClosed
        dialog.setLocationRelativeTo(mainPanel);

        dialog.addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosed(java.awt.event.WindowEvent e) {
                ownerFrame.dispose();
            }
        });

        dialog.setLayout(new BorderLayout(0, 0));


        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS));
        topPanel.setBorder(BorderFactory.createEmptyBorder(8, 12, 6, 12));

        JLabel title = new JLabel("Regex Builder 101");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 13f));
        title.setAlignmentX(Component.LEFT_ALIGNMENT);

        JTextArea instructions = new JTextArea(
            "1. Highlight the value you want to extract\n" +
            "2. Click 'Build Regex'\n" +
            "3. Check that the extracted value is correct\n" +
            "4. Click 'Use this' to apply"
        );
        instructions.setEditable(false);
        instructions.setFocusable(false);
        instructions.setOpaque(false);
        instructions.setBackground(null);
        instructions.setFont(instructions.getFont().deriveFont(11f));
        instructions.setWrapStyleWord(true);
        instructions.setLineWrap(true);
        instructions.setAlignmentX(Component.LEFT_ALIGNMENT);

        topPanel.add(title);
        topPanel.add(Box.createVerticalStrut(4));
        topPanel.add(instructions);

        dialog.add(topPanel, BorderLayout.NORTH);


        JTextArea responseArea = new JTextArea();
        responseArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        responseArea.setLineWrap(false);
        JScrollPane responseScroll = new JScrollPane(responseArea);
        responseScroll.setBorder(BorderFactory.createTitledBorder("Sample Response"));


        JTextField patternField = new JTextField();
        patternField.setFont(new Font("Monospaced", Font.PLAIN, 13));
        patternField.setEditable(true);

        JTextArea testResultArea = new JTextArea(3, 0);
        testResultArea.setEditable(false);
        testResultArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        testResultArea.setLineWrap(true);
        testResultArea.setWrapStyleWord(true);
        JScrollPane testScroll = new JScrollPane(testResultArea);
        testScroll.setBorder(BorderFactory.createTitledBorder("Test Result"));

        JPanel bottomPanel = new JPanel(new BorderLayout(0, 6));
        bottomPanel.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        JPanel patternRow = new JPanel(new BorderLayout(6, 0));
        patternRow.add(new JLabel("Pattern: "), BorderLayout.WEST);
        patternRow.add(patternField, BorderLayout.CENTER);

        JButton buildBtn = new JButton("Build Regex");
        buildBtn.setFont(buildBtn.getFont().deriveFont(Font.BOLD, 12f));
        buildBtn.setFocusPainted(false);
        patternRow.add(buildBtn, BorderLayout.EAST);

        bottomPanel.add(patternRow, BorderLayout.NORTH);
        bottomPanel.add(testScroll, BorderLayout.CENTER);

        JSplitPane centerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        centerSplit.setResizeWeight(0.65);
        centerSplit.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
        centerSplit.setTopComponent(responseScroll);
        centerSplit.setBottomComponent(bottomPanel);
        dialog.add(centerSplit, BorderLayout.CENTER);


        JButton pasteBtn  = new JButton("Paste response");
        JButton clearBtn  = new JButton("Clear");
        JButton testBtn   = new JButton("Test");
        JButton useBtn    = new JButton("Use this");
        JButton cancelBtn = new JButton("Cancel");

        useBtn.setFont(useBtn.getFont().deriveFont(Font.BOLD, 12f));
        useBtn.setEnabled(false);

        JPanel buttonBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 6));
        buttonBar.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0,
            UIManager.getColor("Separator.foreground")));
        buttonBar.add(pasteBtn);
        buttonBar.add(clearBtn);
        buttonBar.add(new JSeparator(JSeparator.VERTICAL) {{
            setPreferredSize(new Dimension(1, 20));
        }});
        buttonBar.add(testBtn);
        buttonBar.add(useBtn);
        buttonBar.add(cancelBtn);
        dialog.add(buttonBar, BorderLayout.SOUTH);


        if (!initialResponse.isEmpty()) {
            responseArea.setText(initialResponse);
        } else {
            responseArea.setText("(No response yet — paste a sample here)");
            responseArea.selectAll();
        }


        pasteBtn.addActionListener(e -> {
            try {
                String clip = (String) Toolkit.getDefaultToolkit()
                    .getSystemClipboard().getData(java.awt.datatransfer.DataFlavor.stringFlavor);
                responseArea.setText(clip);
                responseArea.setCaretPosition(0);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(dialog, "Nothing to paste: " + ex.getMessage());
            }
        });

        clearBtn.addActionListener(e -> responseArea.setText(""));

        buildBtn.addActionListener(e -> {
            String selected = responseArea.getSelectedText();
            if (selected == null || selected.isEmpty()) {
                JOptionPane.showMessageDialog(dialog,
                    "Please highlight the value you want to extract first.",
                    "No selection", JOptionPane.WARNING_MESSAGE);
                return;
            }
            String fullText  = responseArea.getText();
            int selStart     = responseArea.getSelectionStart();
            int selEnd       = responseArea.getSelectionEnd();
            String generated = buildContextAwareRegex(fullText, selStart, selEnd, selected);
            patternField.setText(generated);
            useBtn.setEnabled(true);

            testBtn.doClick();
        });

        testBtn.addActionListener(e -> {
            String pattern = patternField.getText().trim();
            String text    = responseArea.getText();
            if (pattern.isEmpty() || text.isEmpty()) return;
            try {
                java.util.regex.Pattern p = java.util.regex.Pattern.compile(pattern,
                    java.util.regex.Pattern.DOTALL);
                java.util.regex.Matcher m = p.matcher(text);
                if (m.find()) {
                    String match = m.groupCount() >= 1 ? m.group(1) : m.group(0);
                    testResultArea.setForeground(new Color(30, 140, 30));
                    testResultArea.setText("✔ Match found (group 1): " + match);
                    useBtn.setEnabled(true);
                } else {
                    testResultArea.setForeground(new Color(180, 50, 50));
                    testResultArea.setText("✖ No match found. Try adjusting the pattern or your selection.");
                    useBtn.setEnabled(false);
                }
            } catch (java.util.regex.PatternSyntaxException ex) {
                testResultArea.setForeground(new Color(180, 50, 50));
                testResultArea.setText("✖ Invalid regex: " + ex.getMessage());
                useBtn.setEnabled(false);
            }
        });


        patternField.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) { testBtn.doClick(); }
            public void removeUpdate(DocumentEvent e)  { testBtn.doClick(); }
            public void insertUpdate(DocumentEvent e)  { testBtn.doClick(); }
        });

        useBtn.addActionListener(e -> {
            targetValueField.setText(patternField.getText().trim());
            dialog.dispose();
        });

        cancelBtn.addActionListener(e -> dialog.dispose());

        dialog.setVisible(true);
    }

    /**
     * Builds a context-aware regex capture group around the selected substring.
     *
     * Strategy:
     *   1. Look left from selStart for the nearest "anchor" character
     *      (quote, colon, equals, open-bracket, space, or a known HTML/JSON delimiter).
     *   2. Look right from selEnd for the nearest "closing" character
     *      (matching delimiter, semicolon, comma, whitespace, etc.).
     *   3. If both anchors found  →  leftAnchor + CAPTURE + rightAnchor
     *      If only left found     →  leftAnchor + CAPTURE + lookahead-for-newline-or-end
     *      If only right found    →  lookbehind-for-anchor + CAPTURE + rightAnchor
     *      If neither found       →  fallback: literal-escape the selection, wrap in group
     *   4. The capture group itself is built from the character class implied by the
     *      delimiter — e.g. quote delimiter → [^"]+ , angle-bracket → [^<]+ etc.
     */
    private String buildContextAwareRegex(String text, int selStart, int selEnd, String selected) {

        String escapedValue = java.util.regex.Pattern.quote(selected);


        int leftScan   = Math.max(0, selStart - 60);
        String leftCtx = text.substring(leftScan, selStart);


        int rightScan   = Math.min(text.length(), selEnd + 60);
        String rightCtx = text.substring(selEnd, rightScan);


        char leftDelim  = findLeftDelimiter(leftCtx);
        char rightDelim = findRightDelimiter(rightCtx, leftDelim);


        String captureClass = buildCaptureClass(leftDelim, rightDelim);


        String leftAnchorStr  = leftDelim  != 0 ? java.util.regex.Pattern.quote(String.valueOf(leftDelim))  : null;
        String rightAnchorStr = rightDelim != 0 ? java.util.regex.Pattern.quote(String.valueOf(rightDelim)) : null;



        String leftLiteral  = buildLeftLiteral(leftCtx,  leftDelim);
        String rightLiteral = buildRightLiteral(rightCtx, rightDelim);

        if (leftLiteral != null && rightLiteral != null) {
            return leftLiteral + "(" + captureClass + ")" + rightLiteral;
        } else if (leftLiteral != null) {
            return leftLiteral + "(" + captureClass + ")";
        } else if (rightLiteral != null) {
            return "(" + captureClass + ")" + rightLiteral;
        } else {

            return "(" + escapedValue + ")";
        }
    }

    /** Returns the last meaningful delimiter character found scanning left. */
    private char findLeftDelimiter(String leftCtx) {
        char[] anchors = {'"', '\'', '`', '>', '=', ':', '{', '[', '(', ' ', '\n', '\r', ','};
        for (int i = leftCtx.length() - 1; i >= 0; i--) {
            char c = leftCtx.charAt(i);
            for (char a : anchors) if (c == a) return c;
        }
        return 0;
    }

    /** Returns the first closing delimiter found scanning right, aware of the left delimiter. */
    private char findRightDelimiter(String rightCtx, char leftDelim) {

        if (leftDelim == '"' || leftDelim == '\'' || leftDelim == '`') {
            if (rightCtx.indexOf(leftDelim) >= 0) return leftDelim;
        }

        char[] closers = {'"', '\'', '<', '>', '}', ']', ')', ';', ',', ' ', '\n', '\r'};
        for (int i = 0; i < rightCtx.length(); i++) {
            char c = rightCtx.charAt(i);
            for (char cl : closers) if (c == cl) return c;
        }
        return 0;
    }

    /** Builds the regex character class for the capture group. */
    private String buildCaptureClass(char leftDelim, char rightDelim) {

        char boundary = rightDelim != 0 ? rightDelim : leftDelim;
        switch (boundary) {
            case '"':  return "[^\"]+";
            case '\'': return "[^\']+";
            case '<':  return "[^<]+";
            case '>':  return "[^>]+";
            case '}':  return "[^}]+";
            case ']':  return "[^\\]]+";
            case ';':  return "[^;]+";
            case ',':  return "[^,]+";
            case ' ':
            case '\n':
            case '\r': return "\\S+";
            default:   return ".+?";
        }
    }

    /**
     * Extracts a short literal anchor from the left context.
     * Prefers the last 1–3 "stable" characters before the selection
     * (e.g. the closing quote+colon+quote of a JSON key like `"token":"`).
     */
    private String buildLeftLiteral(String leftCtx, char leftDelim) {
        if (leftCtx.isEmpty() || leftDelim == 0) return null;
        int delimPos = leftCtx.lastIndexOf(leftDelim);
        if (delimPos < 0) return null;

        int start = Math.max(0, delimPos - 8);
        String raw = leftCtx.substring(start, delimPos + 1);

        int nl = raw.lastIndexOf('\n');
        int cr = raw.lastIndexOf('\r');
        int cut = Math.max(nl, cr);
        if (cut >= 0) raw = raw.substring(cut + 1);
        return raw.isEmpty() ? null : java.util.regex.Pattern.quote(raw);
    }

    /**
     * Extracts a short literal anchor from the right context.
     */
    private String buildRightLiteral(String rightCtx, char rightDelim) {
        if (rightCtx.isEmpty() || rightDelim == 0) return null;
        int delimPos = rightCtx.indexOf(rightDelim);
        if (delimPos < 0) return null;

        int end = Math.min(rightCtx.length(), delimPos + 5);
        String raw = rightCtx.substring(delimPos, end);
        int nl = raw.indexOf('\n');
        int cr = raw.indexOf('\r');
        int cut = nl >= 0 && cr >= 0 ? Math.min(nl, cr) : Math.max(nl, cr);
        if (cut >= 0) raw = raw.substring(0, cut);

        if (raw.length() > 1 && raw.substring(1).matches("[a-zA-Z0-9_]+")) raw = raw.substring(0, 1);
        return raw.isEmpty() ? null : java.util.regex.Pattern.quote(raw);
    }

    private void updateExampleText(JTextArea area, int type) {
        switch (type) {
            case 0: // Header
                area.setText("Example: Set-Cookie\n" +
                            "Extracts all cookies from\n" +
                            "Set-Cookie headers");
                break;
            case 1: // JSON
                area.setText("Example: ['data']['token']\n" +
                            "For: {\"data\":{\"token\":\"abc\"}}\n" +
                            "Extracts: abc");
                break;
            case 2: // Regex
                area.setText("Example: value=\"([^\"]{1,100})\"\n" +
                            "For: <input value=\"abc123\"/>\n" +
                            "Extracts: abc123 (group 1)");
                break;
        }
    }

    private void exportPipeline() {
        autoSaveRequest();

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Pipeline");
        fileChooser.setFileFilter(new javax.swing.filechooser.FileFilter() {
            public boolean accept(File f) {
                return f.isDirectory() || f.getName().toLowerCase().endsWith(".coookies");
            }
            public String getDescription() {
                return "COOOKIES Pipeline Files (*.coookies)";
            }
        });

        if (fileChooser.showSaveDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            if (!file.getName().toLowerCase().endsWith(".coookies")) {
                file = new File(file.getAbsolutePath() + ".coookies");
            }

            try {
                String jsonData = buildJsonExport();
                FileWriter writer = new FileWriter(file);
                writer.write(jsonData);
                writer.close();

                JOptionPane.showMessageDialog(mainPanel, 
                    "Pipeline exported successfully to:\n" + file.getAbsolutePath(),
                    "Export Success", JOptionPane.INFORMATION_MESSAGE);

            } catch (Exception ex) {
                showError("Error exporting pipeline:\n\n" + ex.getMessage() + 
                        "\n\nStack trace:\n" + getStackTrace(ex));
            }
        }
    }

    private void importPipeline() {
        if (blockedByRunningPipeline()) return;

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Import Pipeline");
        fileChooser.setFileFilter(new javax.swing.filechooser.FileFilter() {
            public boolean accept(File f) {
                return f.isDirectory() || f.getName().toLowerCase().endsWith(".coookies");
            }
            public String getDescription() {
                return "COOOKIES Pipeline Files (*.coookies)";
            }
        });

        if (fileChooser.showOpenDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();

            try {
                StringBuilder sb = new StringBuilder();
                BufferedReader reader = new BufferedReader(new FileReader(file));
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append("\n");
                }
                reader.close();

                String json = sb.toString();

                applyConfigJson(json);

                int expCount = 0;
                synchronized (expirationStrings) {
                    expCount = expirationStrings.size();
                }

                JOptionPane.showMessageDialog(mainPanel,
                    "Pipeline imported successfully!\n\n" +
                    "Requests: " + pipeline.size() + "\n" +
                    "Credentials: " + credentialsTableModel.getRowCount() + "\n" +
                    "Static Variables: " + staticVarsTableModel.getRowCount() + "\n" +
                    "Expiration Strings: " + expCount,
                    "Import Success",
                    JOptionPane.INFORMATION_MESSAGE);


                saveToProject();

            } catch (Exception ex) {
                showError("Error importing pipeline:\n\n" + ex.getMessage() +
                        "\n\nStack trace:\n" + getStackTrace(ex));
            }
        }
    }

    private void clearEditorsForImport() {
        rawRequestEditor.setRequest(HttpRequest.httpRequest("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"));
        rawResponseEditor.setResponse(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n"));
    }

    /**
     * Parses a COOOKIES configuration document (a .coookies file or the copy stored in the
     * Burp project) and replaces the current configuration with it. The document is parsed
     * and validated before anything is cleared, so a bad file leaves the current state intact.
     */
    private void applyConfigJson(String json) throws Exception {
        JsonElement parsed = JsonParser.parseString(json);
        if (!parsed.isJsonObject() || !parsed.getAsJsonObject().has("requests")
                || !parsed.getAsJsonObject().get("requests").isJsonArray()) {
            throw new Exception("Not a COOOKIES configuration: missing \"requests\" array");
        }
        JsonObject root = parsed.getAsJsonObject();

        pipeline.clear();
        refreshPipeline.clear();
        showingRefresh = false;
        requestListModel.clear();
        credentialsTableModel.setRowCount(0);
        staticVarsTableModel.setRowCount(0);
        autoAuthHeadersTableModel.setRowCount(0);
        extractionPanel.removeAll();
        extractionPanel.revalidate();
        extractionPanel.repaint();
        checkpointVarsList.removeAll();
        checkpointValueFields.clear();
        setCheckpointInteractable(false);
        checkpointVarsList.revalidate();
        checkpointVarsList.repaint();
        clearEditorsForImport();

        pipeline.addAll(stepsFromJson(root, "requests"));
        refreshPipeline.addAll(stepsFromJson(root, "refreshPipeline"));
        for (PipelineRequest req : pipeline) {
            requestListModel.addElement(req);
        }

        for (JsonObject credObj : jsonObjects(root, "credentials")) {
            credentialsTableModel.addRow(new Object[]{jsonString(credObj, "username"), jsonString(credObj, "password")});
        }

        for (JsonObject varObj : jsonObjects(root, "staticVariables")) {
            staticVarsTableModel.addRow(new Object[]{jsonString(varObj, "name"), jsonString(varObj, "value")});
        }

        for (JsonObject headerObj : jsonObjects(root, "autoAuthHeaders")) {
            autoAuthHeadersTableModel.addRow(new Object[]{jsonString(headerObj, "name"), jsonString(headerObj, "value")});
        }

        JsonElement expElement = root.get("expirationStrings");
        if (expElement != null && expElement.isJsonArray()) {
            List<String> expLines = new ArrayList<>();
            for (JsonElement exp : expElement.getAsJsonArray()) {
                if (exp.isJsonPrimitive()) expLines.add(exp.getAsString());
            }
            expirationStringsArea.setText(String.join("\n", expLines));
            updateExpirationStringsList();
        }

        JsonElement configElement = root.get("httpConfig");
        if (configElement != null && configElement.isJsonObject()) {
            JsonObject configObj = configElement.getAsJsonObject();
            configuredPort = jsonInt(configObj, "port", configuredPort);
            JsonElement httpsElement = configObj.get("https");
            if (httpsElement != null && httpsElement.isJsonPrimitive()) {
                configuredHttps = httpsElement.getAsBoolean();
            }

            defaultPortField.setText(String.valueOf(configuredPort));
            forceHttpsCheckbox.setSelected(configuredHttps);
        }

        SessionMode loadedMode = SessionMode.OFF;
        int loadedMinutes = timerIntervalMinutes;
        JsonElement sessionElement = root.get("sessionKeeping");
        JsonElement legacyRefreshElement = root.get("tokenRefresh");
        if (sessionElement != null && sessionElement.isJsonObject()) {
            JsonObject sessionObj = sessionElement.getAsJsonObject();
            loadedMinutes = jsonInt(sessionObj, "intervalMinutes", loadedMinutes);
            try {
                loadedMode = SessionMode.valueOf(jsonString(sessionObj, "mode"));
            } catch (IllegalArgumentException e) {
                loadedMode = SessionMode.OFF;
            }
        } else if (legacyRefreshElement != null && legacyRefreshElement.isJsonObject()) {
            // Configs from before the Session selector: {"enabled": bool, "intervalMinutes": n}
            JsonObject legacyObj = legacyRefreshElement.getAsJsonObject();
            loadedMinutes = jsonInt(legacyObj, "intervalMinutes", loadedMinutes);
            JsonElement enabledElement = legacyObj.get("enabled");
            if (enabledElement != null && enabledElement.isJsonPrimitive() && enabledElement.getAsBoolean()) {
                loadedMode = SessionMode.REFRESH_TIMER;
            }
        }
        applyingConfig = true;
        try {
            timerIntervalSpinner.setValue(Math.max(1, Math.min(100000, loadedMinutes)));
        } finally {
            applyingConfig = false;
        }

        loginViewBtn.setSelected(true);
        refreshViewBtn.setSelected(false);
        refreshControls.setVisible(false);
        addStepTypeBtn.setEnabled(true);

        if (requestListModel.getSize() > 0) {
            requestList.setSelectedIndex(0);
        }
        loadSelectedRequest();

        updateRefreshLock();
        setSessionMode(loadedMode);
    }

    private List<PipelineRequest> stepsFromJson(JsonObject root, String key) {
        List<PipelineRequest> steps = new ArrayList<>();
        for (JsonObject reqObj : jsonObjects(root, key)) {
            PipelineRequest req = new PipelineRequest(jsonString(reqObj, "name"));
            req.stepType = jsonInt(reqObj, "stepType", PipelineRequest.TYPE_HTTP);
            req.rawRequest = jsonString(reqObj, "rawRequest");
            req.authExtraction = specialExtractionFromJson(reqObj, "authExtraction");
            req.refreshTokenExtraction = specialExtractionFromJson(reqObj, "refreshTokenExtraction");

            for (JsonObject extObj : jsonObjects(reqObj, "extractions")) {
                Extraction ext = new Extraction(jsonString(extObj, "name"));
                ext.type = jsonInt(extObj, "type", 0);
                ext.value = jsonString(extObj, "value");
                req.extractions.add(ext);
            }

            for (JsonObject cvObj : jsonObjects(reqObj, "checkpointVariables")) {
                req.checkpointVariables.add(new CheckpointVariable(jsonString(cvObj, "name")));
            }

            steps.add(req);
        }
        return steps;
    }

    private AuthExtraction specialExtractionFromJson(JsonObject reqObj, String key) {
        JsonElement element = reqObj.get(key);
        if (element == null || !element.isJsonObject()) return null;
        AuthExtraction ext = new AuthExtraction();
        ext.type = jsonInt(element.getAsJsonObject(), "type", 0);
        ext.value = jsonString(element.getAsJsonObject(), "value");
        return ext;
    }

    /** The JSON objects inside parent[key]; empty if the key is absent or not an array. */
    private List<JsonObject> jsonObjects(JsonObject parent, String key) {
        List<JsonObject> objects = new ArrayList<>();
        JsonElement element = parent.get(key);
        if (element != null && element.isJsonArray()) {
            for (JsonElement item : element.getAsJsonArray()) {
                if (item.isJsonObject()) objects.add(item.getAsJsonObject());
            }
        }
        return objects;
    }

    private String jsonString(JsonObject obj, String key) {
        JsonElement element = obj.get(key);
        return (element != null && element.isJsonPrimitive()) ? element.getAsString() : "";
    }

    private int jsonInt(JsonObject obj, String key, int defaultValue) {
        JsonElement element = obj.get(key);
        try {
            return (element != null && element.isJsonPrimitive()) ? element.getAsInt() : defaultValue;
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Walks the Swing component tree from the root window looking for the
     * JTabbedPane whose tab components include mainPanel.
     * This is the Burp suite tab bar — NOT the header label inside our own panel.
     */
    private void setTabColor(Color bg, Color fg) {
        if (mainPanel == null) return;
        java.awt.Window root = SwingUtilities.getWindowAncestor(mainPanel);
        if (root == null) return;
        findAndColorTab(root, bg, fg);
    }

    private boolean findAndColorTab(java.awt.Container container, Color bg, Color fg) {
        for (java.awt.Component child : container.getComponents()) {
            if (child instanceof JTabbedPane) {
                JTabbedPane tp = (JTabbedPane) child;
                for (int i = 0; i < tp.getTabCount(); i++) {
                    if (tp.getComponentAt(i) == mainPanel) {

                        tp.setBackgroundAt(i, bg);
                        tp.setForegroundAt(i, fg);
                        return true;
                    }
                }
            }
            if (child instanceof java.awt.Container) {
                if (findAndColorTab((java.awt.Container) child, bg, fg)) return true;
            }
        }
        return false;
    }

    /** Runs a UI update right away when already on the EDT, otherwise queues it. Queuing from the EDT
     *  as well would let the update land after ones the worker thread queues later. */
    private void onEdt(Runnable update) {
        if (SwingUtilities.isEventDispatchThread()) {
            update.run();
        } else {
            SwingUtilities.invokeLater(update);
        }
    }

    private void setStatus(String text, Color color) {
        onEdt(() -> {
            if (statusLabel != null) {
                statusLabel.setText(text);
                statusLabel.setForeground(color != null ? color
                    : UIManager.getColor("Label.disabledForeground"));
            }
        });
    }

    private void executePipeline() {
        if (pipelineRunning.get()) {
            log("Pipeline is already running — ignoring Execute.");
            return;
        }

        autoSaveRequest();

        new Thread(() -> {
            try {
                runPipelineExclusive(true);
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    log("✖ Fatal error: " + e.getMessage());
                    showError("Fatal error during pipeline execution:\n\n" + e.getMessage() + 
                             "\n\nStack trace:\n" + getStackTrace(e));
                    pipelineActiveCredRow = -1;
                    pipelineActiveReqRow  = -1;
                    credentialsTable.repaint();
                    requestList.repaint();
                    setStatus("✖ Fatal error: " + e.getMessage(), new Color(180, 50, 50));
                    setTabColor(null, null);
                });
            }
        }).start();
    }

    /** Runs the pipeline on the calling thread, unless a run (manual or auto-refresh) is already in progress. */
    private void runPipelineExclusive(boolean manual) {
        if (!pipelineRunning.compareAndSet(false, true)) return;
        setRunControlsEnabled(false);
        try {


            if (manual) finalAuthValues.clear();
            executePipelineInBackground(manual);
        } finally {
            lastLoginFinishedAt = System.currentTimeMillis();
            pipelineRunning.set(false);
            setRunControlsEnabled(true);
        }
    }

    /** Copies a two-column table's rows (skipping rows with a null cell), reading it on the EDT:
     *  the worker threads must not walk a table model the user may be editing at that moment. */
    private List<String[]> snapshotTable(DefaultTableModel model) {
        List<String[]> rows = new ArrayList<>();
        Runnable read = () -> {
            for (int i = 0; i < model.getRowCount(); i++) {
                String first = (String) model.getValueAt(i, 0);
                String second = (String) model.getValueAt(i, 1);
                if (first != null && second != null) rows.add(new String[]{first, second});
            }
        };
        if (SwingUtilities.isEventDispatchThread()) {
            read.run();
        } else {
            try {
                SwingUtilities.invokeAndWait(read);
            } catch (Exception e) {
                api.logging().logToError("[COOOKIES] Could not read table: " + e.getMessage());
            }
        }
        return rows;
    }

    private void setRunControlsEnabled(boolean enabled) {
        SwingUtilities.invokeLater(() -> {
            executeBtn.setEnabled(enabled);
            refreshNowBtn.setEnabled(enabled);
        });
    }

    /** interactive: started by the user, so problems may be reported with a dialog. Unattended runs
     *  (expiration strings, login timer) only log, otherwise every failed re-login would stack up another popup. */
    private void executePipelineInBackground(boolean interactive) {
        activeRunIsRefresh = false;
        SwingUtilities.invokeLater(() -> {
            logArea.setText("=== Starting Pipeline Execution ===\n\n");
            setTabColor(new Color(128, 0, 128), new Color(255, 215, 0));
        });
        setStatus("▶ Running…", new Color(30, 140, 30));

        List<String[]> credList = new ArrayList<>();

        for (String[] row : snapshotTable(credentialsTableModel)) {
            if (!row[0].trim().isEmpty()) {
                credList.add(new String[]{row[0].trim(), row[1].trim()});
            }
        }
        List<String[]> staticVars = snapshotTable(staticVarsTableModel);

        if (credList.isEmpty()) {
            log("✗ No valid credentials provided. Use format: username:password");
            if (interactive) showError("No valid credentials provided. Use format: username:password");
            setStatus("Ready", UIManager.getColor("Label.disabledForeground"));
            SwingUtilities.invokeLater(() -> setTabColor(null, null));
            afterLoginRun(false);
            return;
        }

        final int totalCreds = credList.size();
        int successCount = 0;
        int failCount = 0;
        int missingAuthCount = 0;

        for (int i = 0; i < credList.size(); i++) {
            String[] cred = credList.get(i);
            log("\n--- Credential Set " + (i + 1) + ": " + cred[0] + " ---");
            final int credRow = i;
            SwingUtilities.invokeLater(() -> {
                pipelineActiveCredRow = credRow;
                credentialsTable.repaint();
            });

            Map<String, String> variables = new HashMap<>();
            variables.put("USERNAME", cred[0]);
            variables.put("PASSWORD", cred[1]);

            for (String[] staticVar : staticVars) {
                String varName = staticVar[0].trim();
                String varValue = staticVar[1];
                if (!varName.isEmpty()) {
                    variables.put(varName, varValue);
                    log("  Static var '" + varName + "': " + 
                        (varValue.length() > 50 ? varValue.substring(0, 50) + "..." : varValue));
                }
            }

            try {
                final int credIdx = i;
                final String credUser = cred[0];
                final int total = credList.size();
                setStatus("▶ Running · User " + (credIdx+1) + "/" + total + " (" + credUser + ") · Step 0/" + pipeline.size(), new Color(30, 140, 30));
                Map<String, String> userVars = extractedValues.computeIfAbsent(cred[0], k -> new java.util.concurrent.ConcurrentHashMap<>());
                userVars.remove(REFRESH_TOKEN_VAR); // never carry a previous login's refresh token over
                Map<String, String> cookieJar = new LinkedHashMap<>();
                cookieJars.put(cred[0], cookieJar);
                boolean authOk = executePipelineForCredential(pipeline, false, variables, cred[0], userVars, cookieJar);
                if (authOk) {
                    log("✓ Pipeline completed successfully for " + cred[0]);
                    successCount++;
                } else {
                    // The requests went through, but the session wasn't renewed: the login timer treats this as a failure
                    log("⚠ Pipeline completed for " + cred[0] + ", but no Final Auth Value was extracted");
                    missingAuthCount++;
                }
            } catch (Exception e) {
                log("✗ Pipeline failed for " + cred[0] + ": " + e.getMessage());
                final String errorMsg = "Pipeline failed for " + cred[0] + ":\n\n" + e.getMessage() + 
                         "\n\nStack trace:\n" + getStackTrace(e);
                if (interactive) showError(errorMsg);
                failCount++;
            }
        }

        final int finalSuccess = successCount;
        final int finalFail = failCount;
        final int finalMissingAuth = missingAuthCount;
        SwingUtilities.invokeLater(() -> {
            pipelineActiveCredRow = -1;
            pipelineActiveReqRow  = -1;
            credentialsTable.repaint();
            requestList.repaint();
            String summary = "✔ Done · " + finalSuccess + "/" + totalCreds + " users ok";
            if (finalFail > 0) summary += " · " + finalFail + " failed";
            if (finalMissingAuth > 0) summary += " · " + finalMissingAuth + " without auth value";
            setStatus(summary, finalFail + finalMissingAuth > 0 ? new Color(180, 50, 50) : new Color(30, 140, 30));
            setTabColor(null, null);
        });

        log("\n=== Pipeline Execution Complete ===");
        saveToProject();


        afterLoginRun(finalFail == 0 && finalMissingAuth == 0);
    }

    /** A login run finishing is the only thing that starts a session timer. */
    private void afterLoginRun(boolean allUsersOk) {
        if (sessionMode == SessionMode.REFRESH_TIMER) {
            if (anyUserHasRefreshToken()) {
                scheduleSessionTimer();
            } else {
                cancelSessionTimer();
                setTimerStatus("stopped: no refresh token", new Color(180, 50, 50));
                log("Refresh timer: the login run extracted no refresh token, so no refresh is scheduled.");
            }
        } else if (sessionMode == SessionMode.LOGIN_TIMER) {
            if (allUsersOk) {
                scheduleSessionTimer();
            } else {
                cancelSessionTimer();
                setTimerStatus("stopped: login failed", new Color(180, 50, 50));
                log("Login timer: stopped because the login failed for at least one user. Run the login pipeline to resume.");
            }
        }
    }

    /** Blocks the pipeline WORKER thread (not the EDT) until the user clicks Continue on this
     *  checkpoint step. Whatever values are in the fields at click time are merged into userVars. */
    private void waitForCheckpoint(int stepIdx, PipelineRequest req, Map<String, String> userVars) throws InterruptedException {
        awaitingCheckpoint = true;
        awaitingCheckpointStepIdx = stepIdx;
        SwingUtilities.invokeLater(() -> {
            if (!showingRefresh && requestList.getSelectedIndex() == stepIdx) {
                setCheckpointInteractable(true);
            }
        });

        checkpointContinueSignal.take(); // parks this worker thread only — UI stays fully responsive

        Map<String, String> values = pendingCheckpointValues;
        pendingCheckpointValues = null;
        if (values != null) {
            userVars.putAll(values);
        }

        awaitingCheckpoint = false;
        awaitingCheckpointStepIdx = -1;
        SwingUtilities.invokeLater(() -> {
            if (!showingRefresh && requestList.getSelectedIndex() == stepIdx) {
                setCheckpointInteractable(false);
            }
        });
    }

    /**
     * Runs one pipeline (Login or Refresh) for one credential. userVars and cookieJar are read and
     * updated in place. In a refresh run a failed auth / refresh-token extraction is an error,
     * since carrying on would leave the session with stale tokens.
     */
    private boolean executePipelineForCredential(List<PipelineRequest> steps, boolean isRefresh, Map<String, String> variables,
                                                 String username, Map<String, String> userVars,
                                                 Map<String, String> cookieJar) throws Exception {
        final String runLabel = isRefresh ? "🔄 Refreshing" : "▶ Running";
        boolean authOk = true; // false if an Auth extraction was defined but extracted nothing

        for (int i = 0; i < steps.size(); i++) {
            PipelineRequest req = steps.get(i);
            log("\n  Request " + (i + 1) + ": " + req.name);
            final int stepIdx = i;
            final String stepUser = username;
            final int totalSteps = steps.size();
            final int totalCreds2 = credentialsTableModel.getRowCount();
            final boolean isCheckpoint = (req.stepType == PipelineRequest.TYPE_CHECKPOINT);
            SwingUtilities.invokeLater(() -> {
                pipelineActiveReqRow = stepIdx;
                requestList.repaint();

                for (int ci = 0; ci < credentialsTableModel.getRowCount(); ci++) {
                    if (stepUser.equals(credentialsTableModel.getValueAt(ci, 0))) {
                        pipelineActiveCredRow = ci;
                        break;
                    }
                }
                credentialsTable.repaint();
                if (isCheckpoint) {
                    setStatus("⏸ Checkpoint · User " + (pipelineActiveCredRow+1) + "/" + totalCreds2
                        + " (" + stepUser + ") · Step " + (stepIdx+1) + "/" + totalSteps
                        + " (" + req.name + ")", new Color(200, 140, 0));
                    if (showingRefresh) showPipeline(false);
                    requestList.setSelectedIndex(stepIdx); // jump so the checkpoint panel is visible right away
                } else {
                    setStatus(runLabel + " · User " + (pipelineActiveCredRow+1) + "/" + totalCreds2
                        + " (" + stepUser + ") · Step " + (stepIdx+1) + "/" + totalSteps
                        + " (" + req.name + ")", new Color(30, 140, 30));
                }
            });

            if (isCheckpoint) {
                log("    ⏸ Checkpoint reached — waiting for manual continue…");
                waitForCheckpoint(stepIdx, req, userVars);
                log("    ▶ Continued by user.");
                continue;
            }

            String allCookies = buildCookieHeaderValue(cookieJar);

            String processedRequest = req.rawRequest;
            processedRequest = processedRequest.replace("<COOOKIES:USERNAME>", variables.get("USERNAME"));
            processedRequest = processedRequest.replace("<COOOKIES:PASSWORD>", variables.get("PASSWORD"));
            processedRequest = processedRequest.replace("<COOOKIES:COOKIES>", allCookies);

            for (Map.Entry<String, String> entry : variables.entrySet()) {
                if (!entry.getKey().equals("USERNAME") && !entry.getKey().equals("PASSWORD")) {
                    processedRequest = processedRequest.replace("<COOOKIES:" + entry.getKey() + ">", entry.getValue());
                }
            }



            for (Map.Entry<String, String> entry : userVars.entrySet()) {
                processedRequest = processedRequest.replace("<COOOKIES:" + entry.getKey() + ">", entry.getValue());
            }



            for (Map.Entry<String, String> entry : userVars.entrySet()) {
                String pattern = "<COOOKIES:" + username + ":" + entry.getKey() + ">";
                processedRequest = processedRequest.replace(pattern, entry.getValue());
            }

            if (finalAuthValues.containsKey(username)) {
                String authPattern = "<__COOOKIES__:" + username + ">";
                processedRequest = processedRequest.replace(authPattern, finalAuthValues.get(username));
            }

            HttpRequest httpRequest = HttpRequest.httpRequest(processedRequest);

            if (httpRequest.body().length() > 0) {
                httpRequest = httpRequest.withUpdatedHeader("Content-Length", String.valueOf(httpRequest.body().length()));
            }

            String host = null;
            int port = 80;
            boolean isHttps = false;
            port = configuredPort;

            for (HttpHeader header : httpRequest.headers()) {
                if (header.name().equalsIgnoreCase("Host")) {
                    String hostHeader = header.value();
                    if (hostHeader.contains(":")) {
                        String[] parts = hostHeader.split(":", 2);
                        host = parts[0];
                        port = Integer.parseInt(parts[1]);
                    } else {
                        host = hostHeader;
                    }
                    break;
                }
            }

            isHttps = configuredHttps;

            if (host == null) {
                throw new Exception("Could not determine host from request: " + req.name);
            }

            log("    Host: " + host + ":" + port + " (HTTPS: " + isHttps + ")");

            HttpRequest requestWithService = httpRequest.withService(
                burp.api.montoya.http.HttpService.httpService(host, port, isHttps)
            );

            HttpRequestResponse requestResponse = api.http().sendRequest(requestWithService);

            if (requestResponse == null || requestResponse.response() == null) {
                throw new Exception("No response received for request: " + req.name);
            }

            HttpResponse response = requestResponse.response();
            String responseStr = response.toString();

            req.lastResponse = responseStr;

            for (HttpHeader header : response.headers()) {
                if (header.name().equalsIgnoreCase("set-cookie")) {
                    applySetCookie(cookieJar, header.value());
                }
            }

            final int currentIdx = i;
            SwingUtilities.invokeLater(() -> {
                if (showingRefresh == isRefresh && requestList.getSelectedIndex() == currentIdx) {
                    rawResponseEditor.setResponse(response);
                }
            });

            log("    Status: " + response.statusCode());

            for (Extraction ext : req.extractions) {
                String extracted = performExtraction(ext.type, ext.value, response, responseStr);

                if (extracted != null) {
                    userVars.put(ext.name, extracted);
                    variables.put(ext.name, extracted);
                    log("    Extracted '" + ext.name + "' -> <COOOKIES:" + username + ":" + ext.name + ">: " + 
                        (extracted.length() > 50 ? extracted.substring(0, 50) + "..." : extracted));
                } else {
                    log("    Warning: Extraction '" + ext.name + "' failed");
                }
            }

            if (req.authExtraction != null) {
                String extracted = performExtraction(req.authExtraction.type, req.authExtraction.value, 
                                                    response, responseStr);

                if (extracted != null) {
                    finalAuthValues.put(username, extracted);
                    log("    ⭐ Final Auth Value -> <__COOOKIES__:" + username + ">: " + 
                        (extracted.length() > 50 ? extracted.substring(0, 50) + "..." : extracted));
                } else if (isRefresh) {
                    throw new Exception("Auth extraction failed in refresh step: " + req.name);
                } else {
                    log("    Warning: Auth extraction failed");
                    authOk = false;
                }
            }

            if (req.refreshTokenExtraction != null) {
                String extracted = performExtraction(req.refreshTokenExtraction.type, req.refreshTokenExtraction.value,
                                                    response, responseStr);

                if (extracted != null) {
                    userVars.put(REFRESH_TOKEN_VAR, extracted);
                    log("    🔄 Refresh Token -> <COOOKIES:" + username + ":" + REFRESH_TOKEN_VAR + ">: " +
                        (extracted.length() > 50 ? extracted.substring(0, 50) + "..." : extracted));
                } else if (isRefresh) {
                    throw new Exception("Refresh token extraction failed in refresh step: " + req.name);
                } else {
                    log("    Warning: Refresh token extraction failed");
                }
            }
        }
        return authOk;
    }



    private boolean anyUserHasRefreshToken() {
        for (Map<String, String> userVars : extractedValues.values()) {
            if (userVars.containsKey(REFRESH_TOKEN_VAR)) return true;
        }
        return false;
    }

    private synchronized boolean isSessionTimerScheduled() {
        return refreshTask != null && !refreshTask.isCancelled();
    }

    /**
     * (Re)starts the countdown: the Login or Refresh pipeline (per sessionMode) runs every
     * timerIntervalMinutes from now. Only called when a login run finishes with a timer mode on.
     * The scheduler only polls a wall-clock deadline every few seconds. That way a refresh that comes
     * due while another run holds the pipeline is retried seconds later instead of a whole interval
     * later, and a deadline that passed while the machine was asleep fires as soon as it wakes.
     */
    private synchronized void scheduleSessionTimer() {
        if (refreshTask != null) refreshTask.cancel(false);
        refreshTask = null;
        if (!sessionMode.timer) return;

        if (refreshScheduler == null) {
            refreshScheduler = java.util.concurrent.Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "coookies-token-refresh");
                t.setDaemon(true);
                return t;
            });
        }

        nextTimerRunAtMillis = System.currentTimeMillis() + timerIntervalMinutes * 60_000L;
        refreshTask = refreshScheduler.scheduleWithFixedDelay(
            this::sessionTimerTick, 5, 5, java.util.concurrent.TimeUnit.SECONDS);
        setTimerStatus(nextTimerRunText(), null);
    }

    private void sessionTimerTick() {
        SessionMode mode = sessionMode;
        try {
            if (System.currentTimeMillis() < nextTimerRunAtMillis || pipelineRunning.get()) return;
            if (mode == SessionMode.REFRESH_TIMER) {
                runRefreshExclusive(false);
            } else if (mode == SessionMode.LOGIN_TIMER) {
                log("\n=== Login timer: re-running the login pipeline ===");
                runPipelineExclusive(false); // its end (afterLoginRun) restarts or stops the countdown
            }
        } catch (Throwable t) {
            // Anything escaping a scheduled task would silently cancel its future runs
            api.logging().logToError("[COOOKIES] Session timer run failed: " + t);
            if (mode == SessionMode.LOGIN_TIMER) {
                cancelSessionTimer();
                setTimerStatus("stopped: login error", new Color(180, 50, 50));
                setStatus("✖ Timed login failed · timer stopped", new Color(180, 50, 50));
                SwingUtilities.invokeLater(() -> setTabColor(null, null));
            }
        }
    }

    private synchronized void cancelSessionTimer() {
        if (refreshTask != null) refreshTask.cancel(false);
        refreshTask = null;
    }

    private synchronized void shutdownSessionTimer() {
        cancelSessionTimer();
        if (refreshScheduler != null) refreshScheduler.shutdownNow();
        refreshScheduler = null;
    }

    private String nextTimerRunText() {
        return "next run at " + java.time.Instant.ofEpochMilli(nextTimerRunAtMillis)
            .atZone(java.time.ZoneId.systemDefault())
            .format(java.time.format.DateTimeFormatter.ofPattern("HH:mm"));
    }

    private void setTimerStatus(String text, Color color) {
        onEdt(() -> {
            timerStatusLabel.setText(text);
            timerStatusLabel.setForeground(color != null ? color
                : UIManager.getColor("Label.disabledForeground"));
        });
    }

    private void refreshNow() {
        if (pipelineRunning.get()) {
            log("A pipeline run is already in progress — ignoring Refresh now.");
            return;
        }
        autoSaveRequest();
        new Thread(() -> runRefreshExclusive(true), "coookies-token-refresh-manual").start();
    }

    /** Runs the Refresh pipeline on the calling thread unless another run is in progress.
     *  A failed run stops the timer until the Login pipeline is run again. */
    private void runRefreshExclusive(boolean manual) {
        if (!pipelineRunning.compareAndSet(false, true)) {
            log("Token refresh skipped: a pipeline run is already in progress.");
            return;
        }

        setRunControlsEnabled(false);
        boolean ok = false;
        try {
            ok = executeRefreshInBackground();
        } catch (Exception e) {
            log("✖ Token refresh error: " + e.getMessage());
            api.logging().logToError("[COOOKIES] Token refresh error: " + e.getMessage());
        } finally {
            pipelineRunning.set(false);
            setRunControlsEnabled(true);
        }

        if (sessionMode != SessionMode.REFRESH_TIMER) return;

        if (!ok) {
            cancelSessionTimer();
            log("Refresh timer: stopped after a failed refresh. Run the login pipeline to resume.");
            setTimerStatus("stopped: refresh failed", new Color(180, 50, 50));
            setStatus("✖ Token refresh failed · timer stopped", new Color(180, 50, 50));
        } else if (isSessionTimerScheduled()) {
            // Tokens are fresh again, so a running countdown moves on; a refresh never starts one
            nextTimerRunAtMillis = System.currentTimeMillis() + timerIntervalMinutes * 60_000L;
            setTimerStatus(nextTimerRunText(), null);
        }
    }

    /** Runs the Refresh pipeline once for every user holding a refresh token.
     *  Returns false if any user failed or there was nothing to refresh. */
    private boolean executeRefreshInBackground() {
        activeRunIsRefresh = true;
        log("\n=== Token Refresh started at " + java.time.LocalTime.now()
            .format(java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss")) + " ===");
        SwingUtilities.invokeLater(() -> {
            setStatus("🔄 Refreshing tokens…", new Color(30, 140, 30));
            setTabColor(new Color(128, 0, 128), new Color(255, 215, 0));
        });

        int okCount = 0;
        int failCount = 0;
        String problem = null;

        try {
            if (refreshPipeline.isEmpty()) {
                problem = "the Refresh pipeline has no steps";
                return false;
            }

            List<String[]> staticVars = snapshotTable(staticVarsTableModel);

            for (String[] cred : snapshotTable(credentialsTableModel)) {
                if (cred[0].trim().isEmpty()) continue;
                final String username = cred[0].trim();
                String rawPassword = cred[1];

                Map<String, String> currentVars = extractedValues.get(username);
                if (currentVars == null || !currentVars.containsKey(REFRESH_TOKEN_VAR)) {
                    log("\n--- " + username + ": no refresh token, skipped ---");
                    continue;
                }

                log("\n--- Refreshing: " + username + " ---");

                Map<String, String> variables = new HashMap<>();
                variables.put("USERNAME", username);
                variables.put("PASSWORD", rawPassword.trim());
                for (String[] staticVar : staticVars) {
                    if (!staticVar[0].trim().isEmpty()) {
                        variables.put(staticVar[0].trim(), staticVar[1]);
                    }
                }


                Map<String, String> newVars = new java.util.concurrent.ConcurrentHashMap<>(currentVars);
                Map<String, String> currentJar = cookieJars.get(username);
                Map<String, String> newJar = currentJar != null ? new LinkedHashMap<>(currentJar) : new LinkedHashMap<>();
                String oldAuth = finalAuthValues.get(username);

                try {
                    executePipelineForCredential(refreshPipeline, true, variables, username, newVars, newJar);
                    extractedValues.put(username, newVars);
                    cookieJars.put(username, newJar);
                    log("✓ Refreshed " + username);
                    okCount++;
                } catch (Exception e) {
                    if (oldAuth != null) {
                        finalAuthValues.put(username, oldAuth);
                    } else {
                        finalAuthValues.remove(username);
                    }
                    log("✗ Refresh failed for " + username + ": " + e.getMessage() + " (previous values kept)");
                    failCount++;
                }
            }

            if (okCount == 0 && failCount == 0) {
                problem = "no user has a refresh token yet — run the login pipeline first";
                return false;
            }
            return failCount == 0;
        } finally {
            activeRunIsRefresh = false;
            final String summary;
            final boolean clean = problem == null && failCount == 0;
            if (problem != null) {
                log("✗ Nothing refreshed: " + problem);
                summary = "✖ Token refresh: " + problem;
            } else {
                summary = "🔄 Tokens refreshed · " + okCount + "/" + (okCount + failCount) + " users ok"
                    + (failCount > 0 ? " · " + failCount + " failed" : "");
            }
            SwingUtilities.invokeLater(() -> {
                pipelineActiveCredRow = -1;
                pipelineActiveReqRow  = -1;
                credentialsTable.repaint();
                requestList.repaint();
                setTabColor(null, null);
            });
            setStatus(summary, clean ? new Color(30, 140, 30) : new Color(180, 50, 50));
            log("\n=== Token Refresh complete ===");
        }
    }

    private String performExtraction(int type, String value, HttpResponse response, String responseStr) {
        String extracted = null;

        if (type == 0) { // Header
            List<burp.api.montoya.http.message.HttpHeader> headers = response.headers();
            for (burp.api.montoya.http.message.HttpHeader header : headers) {
                if (header.name().equalsIgnoreCase(value)) {
                    extracted = header.value();

                    if (value.equalsIgnoreCase("set-cookie")) {
                        List<String> cookieValues = new ArrayList<>();
                        for (burp.api.montoya.http.message.HttpHeader h : headers) {
                            if (h.name().equalsIgnoreCase("set-cookie")) {
                                String cookieHeader = h.value();
                                String cookieValue = cookieHeader.split(";")[0].trim();
                                cookieValues.add(cookieValue);
                            }
                        }
                        extracted = String.join("; ", cookieValues);
                    }
                    break;
                }
            }
        } else if (type == 1) { // JSON
            String body = response.bodyToString();
            extracted = extractJsonValue(body, value);
        } else if (type == 2) { // Regex
            Pattern pattern = Pattern.compile(value);
            Matcher matcher = pattern.matcher(responseStr);
            if (matcher.find() && matcher.groupCount() >= 1) {
                extracted = matcher.group(1);
            }
        }

        return extracted;
    }

    /** Applies one Set-Cookie header value to the jar: stores name=value, or drops the cookie if the server expired it. */
    private void applySetCookie(Map<String, String> jar, String setCookieValue) {
        String[] parts = setCookieValue.split(";");
        String pair = parts[0].trim();
        int eq = pair.indexOf('=');
        if (eq <= 0) return;

        String name = pair.substring(0, eq).trim();
        String value = pair.substring(eq + 1).trim();

        if (isCookieExpired(parts)) {
            jar.remove(name);
        } else {
            jar.put(name, value);
        }
    }

    /** True if the Set-Cookie attributes delete the cookie (Max-Age <= 0, or Expires in the past). Max-Age wins over Expires. */
    private boolean isCookieExpired(String[] setCookieParts) {
        String expires = null;
        for (int i = 1; i < setCookieParts.length; i++) {
            String attr = setCookieParts[i].trim();
            int eq = attr.indexOf('=');
            if (eq <= 0) continue;
            String attrName = attr.substring(0, eq).trim();
            String attrValue = attr.substring(eq + 1).trim();

            if (attrName.equalsIgnoreCase("max-age")) {
                try {
                    return Long.parseLong(attrValue) <= 0;
                } catch (NumberFormatException e) {

                }
            } else if (attrName.equalsIgnoreCase("expires")) {
                expires = attrValue;
            }
        }

        if (expires != null) {
            for (String format : new String[]{"EEE, dd MMM yyyy HH:mm:ss zzz", "EEE, dd-MMM-yyyy HH:mm:ss zzz", "EEE, dd-MMM-yy HH:mm:ss zzz"}) {
                try {
                    java.time.ZonedDateTime when = java.time.ZonedDateTime.parse(expires,
                        java.time.format.DateTimeFormatter.ofPattern(format, Locale.ENGLISH));
                    return when.isBefore(java.time.ZonedDateTime.now());
                } catch (java.time.format.DateTimeParseException e) {

                }
            }
        }
        return false;
    }

    private String buildCookieHeaderValue(Map<String, String> jar) {
        List<String> pairs = new ArrayList<>();
        for (Map.Entry<String, String> cookie : jar.entrySet()) {
            pairs.add(cookie.getKey() + "=" + cookie.getValue());
        }
        return String.join("; ", pairs);
    }

    private static final Pattern JSON_PATH_SEGMENT = Pattern.compile("\\[\\s*(?:'([^']*)'|\"([^\"]*)\"|(\\d+))\\s*\\]");

    /**
     * Resolves a path like ['data']['items'][0]['token'] against the parsed JSON body.
     * Strings are returned unescaped, numbers/booleans as written, objects/arrays as compact JSON.
     * Returns null if the body isn't JSON, the path doesn't resolve, or the value is JSON null.
     */
    private String extractJsonValue(String json, String path) {
        try {
            JsonElement current = JsonParser.parseString(json);

            Matcher segments = JSON_PATH_SEGMENT.matcher(path);
            boolean anySegment = false;
            while (segments.find()) {
                anySegment = true;
                if (segments.group(3) != null) {
                    if (current.isJsonArray()) {
                        int index = Integer.parseInt(segments.group(3));
                        if (index >= current.getAsJsonArray().size()) return null;
                        current = current.getAsJsonArray().get(index);
                    } else if (current.isJsonObject()) {
                        current = current.getAsJsonObject().get(segments.group(3));
                    } else {
                        return null;
                    }
                } else {
                    String key = segments.group(1) != null ? segments.group(1) : segments.group(2);
                    if (!current.isJsonObject()) return null;
                    current = current.getAsJsonObject().get(key);
                }
                if (current == null) return null;
            }


            if (!anySegment && !path.trim().isEmpty()) {
                if (!current.isJsonObject()) return null;
                current = current.getAsJsonObject().get(path.trim());
                if (current == null) return null;
            }

            if (current.isJsonNull()) return null;
            if (current.isJsonPrimitive()) return current.getAsString();
            return current.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private String highlightMatch(String text, int start, int end) {
        int contextStart = Math.max(0, start - 30);
        int contextEnd = Math.min(text.length(), end + 30);
        String before = text.substring(contextStart, start);
        String match = text.substring(start, end);
        String after = text.substring(end, contextEnd);
        return "..." + before + "[[[" + match + "]]]" + after + "...";
    }

    private void log(String message) {
        onEdt(() -> {
            logArea.append(message + "\n");
            if (logArea.getDocument().getLength() > 400_000) {
                try {
                    logArea.getDocument().remove(0, 200_000); // drop the oldest half
                } catch (BadLocationException ignored) {
                }
            }
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    private void showError(String message) {
        SwingUtilities.invokeLater(() -> {
            JTextArea textArea = new JTextArea(message);
            textArea.setEditable(false);
            textArea.setLineWrap(true);
            textArea.setWrapStyleWord(true);
            JScrollPane scrollPane = new JScrollPane(textArea);
            scrollPane.setPreferredSize(new Dimension(500, 300));
            JOptionPane.showMessageDialog(mainPanel, scrollPane, "Error", JOptionPane.ERROR_MESSAGE);
        });
    }

    private String getStackTrace(Exception e) {
        StringBuilder sb = new StringBuilder();
        for (StackTraceElement element : e.getStackTrace()) {
            sb.append(element.toString()).append("\n");
        }
        return sb.toString();
    }

    private static final String PROJECT_DATA_KEY = "coookies_config";

    private void saveToProject() {
        try {
            autoSaveRequest();
            String json = buildJsonExport();
            api.persistence().extensionData().setString(PROJECT_DATA_KEY, json);
            api.logging().logToOutput("[COOOKIES] Configuration saved to project.");
        } catch (Exception e) {
            api.logging().logToError("[COOOKIES] Failed to save configuration to project: " + e.getMessage());
        }
    }

    private void loadFromProject() {
        try {
            String json = api.persistence().extensionData().getString(PROJECT_DATA_KEY);
            if (json == null || json.trim().isEmpty()) {
                api.logging().logToOutput("[COOOKIES] No saved configuration found in project.");
                return;
            }

            applyConfigJson(json);
            api.logging().logToOutput("[COOOKIES] Configuration loaded from project: " +
                pipeline.size() + " requests, " +
                credentialsTableModel.getRowCount() + " credentials, " +
                staticVarsTableModel.getRowCount() + " static variables.");

        } catch (Exception e) {
            api.logging().logToError("[COOOKIES] Failed to load configuration from project: " + e.getMessage());
        }
    }

    private static final Gson CONFIG_GSON = new GsonBuilder()
        .setPrettyPrinting()
        .disableHtmlEscaping()
        .serializeNulls()
        .create();

    private String buildJsonExport() {
        JsonObject root = new JsonObject();

        root.add("requests", stepsToJson(pipeline));
        root.add("refreshPipeline", stepsToJson(refreshPipeline));

        root.add("credentials", tableToJson(credentialsTableModel, "username", "password"));
        root.add("staticVariables", tableToJson(staticVarsTableModel, "name", "value"));
        root.add("autoAuthHeaders", tableToJson(autoAuthHeadersTableModel, "name", "value"));

        JsonArray expirations = new JsonArray();
        updateExpirationStringsList();
        synchronized (expirationStrings) {
            for (String expirationString : expirationStrings) {
                expirations.add(expirationString);
            }
        }
        root.add("expirationStrings", expirations);

        JsonObject httpConfig = new JsonObject();
        httpConfig.addProperty("port", configuredPort);
        httpConfig.addProperty("https", configuredHttps);
        root.add("httpConfig", httpConfig);

        JsonObject sessionKeeping = new JsonObject();
        sessionKeeping.addProperty("mode", sessionMode.name());
        sessionKeeping.addProperty("intervalMinutes", timerIntervalMinutes);
        root.add("sessionKeeping", sessionKeeping);

        return CONFIG_GSON.toJson(root);
    }

    private JsonArray stepsToJson(List<PipelineRequest> steps) {
        JsonArray requests = new JsonArray();
        for (PipelineRequest req : steps) {
            JsonObject reqObj = new JsonObject();
            reqObj.addProperty("name", req.name);
            reqObj.addProperty("stepType", req.stepType);
            reqObj.addProperty("rawRequest", req.rawRequest);
            reqObj.add("authExtraction", specialExtractionToJson(req.authExtraction));
            reqObj.add("refreshTokenExtraction", specialExtractionToJson(req.refreshTokenExtraction));

            JsonArray extractions = new JsonArray();
            for (Extraction ext : req.extractions) {
                JsonObject extObj = new JsonObject();
                extObj.addProperty("name", ext.name);
                extObj.addProperty("type", ext.type);
                extObj.addProperty("value", ext.value);
                extractions.add(extObj);
            }
            reqObj.add("extractions", extractions);

            JsonArray checkpointVariables = new JsonArray();
            for (CheckpointVariable cv : req.checkpointVariables) {
                JsonObject cvObj = new JsonObject();
                cvObj.addProperty("name", cv.name);
                checkpointVariables.add(cvObj);
            }
            reqObj.add("checkpointVariables", checkpointVariables);

            requests.add(reqObj);
        }
        return requests;
    }

    private JsonElement specialExtractionToJson(AuthExtraction ext) {
        if (ext == null) return JsonNull.INSTANCE;
        JsonObject obj = new JsonObject();
        obj.addProperty("type", ext.type);
        obj.addProperty("value", ext.value);
        return obj;
    }

    /** Serializes a two-column table as an array of {firstKey, secondKey} objects, skipping rows with a null cell. */
    private JsonArray tableToJson(DefaultTableModel model, String firstKey, String secondKey) {
        JsonArray rows = new JsonArray();
        for (int i = 0; i < model.getRowCount(); i++) {
            String first = (String) model.getValueAt(i, 0);
            String second = (String) model.getValueAt(i, 1);
            if (first != null && second != null) {
                JsonObject row = new JsonObject();
                row.addProperty(firstKey, first);
                row.addProperty(secondKey, second);
                rows.add(row);
            }
        }
        return rows;
    }

    private String extractCurrentUsername(String request, List<String> usernames) {
        Pattern authPattern = Pattern.compile("<__COOOKIES__:([^>]+)>");
        Matcher authMatcher = authPattern.matcher(request);
        if (authMatcher.find()) {
            String username = authMatcher.group(1);
            if (usernames.contains(username)) {
                return username;
            }
        }

        Pattern varPattern = Pattern.compile("<COOOKIES:([^:>]+):");
        Matcher varMatcher = varPattern.matcher(request);
        if (varMatcher.find()) {
            String username = varMatcher.group(1);
            if (usernames.contains(username)) {
                return username;
            }
        }

        return null;
    }

    private String rollUsernameInPatterns(String request, String currentUsername, String nextUsername) {
        request = request.replace(
            "<__COOOKIES__:" + currentUsername + ">",
            "<__COOOKIES__:" + nextUsername + ">"
        );

        Pattern varPattern = Pattern.compile("<COOOKIES:" + Pattern.quote(currentUsername) + ":([^>]+)>");
        Matcher matcher = varPattern.matcher(request);
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            String varName = matcher.group(1);
            matcher.appendReplacement(sb, "<COOOKIES:" + nextUsername + ":" + varName + ">");
        }
        matcher.appendTail(sb);

        return sb.toString();
    }

    private void attachEasterEggListener() {
        javax.swing.Timer timer = new javax.swing.Timer(1500, e -> {
            for (Window w : Window.getWindows()) {
                if (findAndAttachToTabLabel(w)) break;
            }
        });
        timer.setRepeats(false);
        timer.start();
    }

    private boolean findAndAttachToTabLabel(Component root) {
        if (root instanceof JLabel) {
            JLabel lbl = (JLabel) root;
            if ("COOOKIES".equals(lbl.getText())) {
                lbl.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent ev) {
                        long now = System.currentTimeMillis();
                        if (eggClickCount == 0 || (now - eggFirstClickTime) > EGG_CLICK_WINDOW) {
                            eggClickCount     = 1;
                            eggFirstClickTime = now;
                        } else {
                            eggClickCount++;
                        }
                        if (eggClickCount >= EGG_CLICKS_NEEDED) {
                            eggClickCount = 0;
                            toggleEasterEgg();
                        }
                    }
                });
                return true;
            }
        }
        if (root instanceof Container) {
            for (Component child : ((Container) root).getComponents()) {
                if (findAndAttachToTabLabel(child)) return true;
            }
        }
        return false;
    }

    private void toggleEasterEgg() {
        if (easterEggPlayer != null && easterEggPlayer.isPlaying()) {
            easterEggPlayer.stop();
            easterEggPlayer = null;
        } else {
            easterEggPlayer = new EasterEggPlayer(api);
            easterEggPlayer.play();
        }
    }

    class EasterEggPlayer {
        private final MontoyaApi api;
        private volatile javazoom.jl.player.Player player;
        private volatile boolean playing = false;
        private Thread playThread;

        EasterEggPlayer(MontoyaApi api) {
            this.api = api;
        }

        boolean isPlaying() { return playing; }

        void play() {
            try {
                InputStream stream = getClass().getResourceAsStream("/coookies");
                if (stream == null) {
                    return;
                }
                player = new javazoom.jl.player.Player(stream);
                playing = true;
                playThread = new Thread(() -> {
                    try {
                        player.play();
                    } catch (Exception ignored) {
                    } finally {
                        playing = false;
                    }
                }, "easter-egg-player");
                playThread.setDaemon(true);
                playThread.start();
            } catch (Exception e) {
            }
        }

        void stop() {
            playing = false;
            if (player != null) {
                try { player.close(); } catch (Exception ignored) {}
            }
            if (playThread != null) {
                playThread.interrupt();
            }
        }
    }


    class PipelineRequest {
        static final int TYPE_HTTP = 0;
        static final int TYPE_CHECKPOINT = 1;

        String name;
        int stepType = TYPE_HTTP;
        String rawRequest;
        String lastResponse;
        List<Extraction> extractions;
        AuthExtraction authExtraction;
        AuthExtraction refreshTokenExtraction;
        List<CheckpointVariable> checkpointVariables;

        PipelineRequest(String name) {
            this.name = name;
            this.rawRequest = "";
            this.lastResponse = null;
            this.extractions = new ArrayList<>();
            this.authExtraction = null;
            this.checkpointVariables = new ArrayList<>();
        }

        @Override
        public String toString() {
            return (stepType == TYPE_CHECKPOINT ? "⏸ " : "") + name;
        }
    }

    class CheckpointVariable {
        String name;

        CheckpointVariable(String name) {
            this.name = name;
        }
    }

    class Extraction {
        String name;
        int type; // 0=Header, 1=JSON, 2=Regex
        String value;

        Extraction(String name) {
            this.name = name;
            this.type = 0;
            this.value = "";
        }
    }

    class AuthExtraction {
        int type; // 0=Header, 1=JSON, 2=Regex
        String value;

        AuthExtraction() {
            this.type = 0;
            this.value = "";
        }
    }
}