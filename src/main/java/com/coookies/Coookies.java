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
    private JTextArea logArea;
    private JTextArea availableVarsArea;
    private List<PipelineRequest> pipeline;
    private int selectedRequestIndex = -1;
    private JTextArea expirationStringsArea;
    private List<String> expirationStrings;
    private volatile boolean isRefreshing = false;
    
    private Map<String, Map<String, String>> extractedValues;
    private final Map<Integer, String> modifiedRequests = Collections.synchronizedMap(new HashMap<>());
    private Map<String, String> finalAuthValues;
    private boolean updateContentLength = false;
    private boolean interceptionEnabled = false;
    private boolean interceptionResEnabled = false;
    private boolean proxyTool = false;
    private boolean proxyToolRes = false;
    private JToggleButton interceptionToggle;
    private JToggleButton ContentLengthToggle;
    private JToggleButton interceptionResToggle;
    private JToggleButton proxyToggle;
    private JToggleButton proxyToggleRes;

    private EasterEggPlayer easterEggPlayer;
    private int   eggClickCount      = 0;
    private long  eggFirstClickTime  = 0;
    private static final int  EGG_CLICKS_NEEDED = 10;
    private static final long EGG_CLICK_WINDOW  = 3000;

    private JTextField defaultPortField;
    private JCheckBox forceHttpsCheckbox;
    private JTextField executePipelineHotkeyField;
    private String executePipelineHotkey = "Ctrl+Shift+Equals";
    private int configuredPort = 443;
    private boolean configuredHttps = true;

    private JLabel statusLabel;
    private volatile int  pipelineActiveCredRow = -1;
    private volatile int  pipelineActiveReqRow  = -1;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.pipeline = new ArrayList<>();
        this.extractedValues = new HashMap<>();
        this.finalAuthValues = new HashMap<>();
        this.expirationStrings = new ArrayList<>();
        
        api.extension().setName("COOOKIES");
        api.http().registerHttpHandler(this);
        api.userInterface().registerContextMenuItemsProvider(this);

        SettingsPanelWithData panel = SettingsPanelBuilder.settingsPanel()
            .withPersistence(SettingsPanelPersistence.USER_SETTINGS)
            .withTitle("COOOKIES Settings")
            .withDescription("IMPORTANT: after editing the Hotkey reload the extension to apply changes")
            .withSettings(
                SettingsPanelSetting.stringSetting("Switch User Hotkey", "Ctrl+Shift+C"),
                SettingsPanelSetting.stringSetting("Execute Pipeline Hotkey", "Ctrl+Shift+Equals")
                )
            .build();
        api.userInterface().registerSettingsPanel(panel);

        String preferredHotkey = panel.getString("Hotkey");
        String savedExecHotkey = panel.getString("ExecutePipelineHotkey");
        if (savedExecHotkey != null && !savedExecHotkey.trim().isEmpty()) {
            executePipelineHotkey = savedExecHotkey.trim();
        }

        api.logging().logToOutput("Switch User Hotkey loaded: "+preferredHotkey);
        api.logging().logToOutput("Execute Pipeline Hotkey loaded: "+executePipelineHotkey);

        HotKey rollCredentialsHotKey = HotKey.hotKey("Roll to next credential", preferredHotkey);

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
                // Silently fail
            }
        });

        api.userInterface().registerHotKeyHandler(
            HotKeyContext.HTTP_MESSAGE_EDITOR,
            rollCredentialsHotKey,
            rollHandler
        );

        HotKey executePipelineHotKey = HotKey.hotKey("Execute COOOKIES Pipeline", executePipelineHotkey);
        HotKeyHandler executeHandler = event -> SwingUtilities.invokeLater(() -> {
            executePipeline();
            setInterception(true);
        });
        api.userInterface().registerHotKeyHandler(
            HotKeyContext.HTTP_MESSAGE_EDITOR,
            executePipelineHotKey,
            executeHandler
        );
        
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
    
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        if (interceptionEnabled) {
            try {
                String requestStr = requestToBeSent.toString();
                
                if (!containsPatterns(requestStr)) {
                    return RequestToBeSentAction.continueWith(requestToBeSent);
                }
                
                String[] resp = replacePatterns(requestStr);

                String username = resp[0];
                String modifiedRequest = resp[1];
                
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
            } catch (Exception e) {
                api.logging().logToError("Error in HTTP interception: " + e.getMessage());
                e.printStackTrace();
            }
        }
        
        return RequestToBeSentAction.continueWith(requestToBeSent);
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

        if (interceptionResEnabled) {
            
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
                    HttpResponse modifiedResponse = HttpResponse.httpResponse(responseStr)
                        .withAddedHeader("Coookies-Expiration", "HIT");
                    
                    if (!isRefreshing) {
                        isRefreshing = true;
                        api.logging().logToOutput("Starting automatic pipeline execution due to session expiration");
                        
                        new Thread(() -> {
                            try {
                                executePipelineInBackground();
                            } catch (Exception e) {
                                api.logging().logToError("Error during automatic pipeline execution: " + e.getMessage());
                                e.printStackTrace();
                            } finally {
                                isRefreshing = false;
                                api.logging().logToOutput("Automatic pipeline execution completed");
                            }
                        }).start();
                    } else {
                        api.logging().logToOutput("Pipeline already refreshing, skipping automatic execution");
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
    
    // ─────────────────────────── NEW UI METHODS ────────────────────────────────

    /** Top header bar: title + pipeline action buttons + interception toggles */
    private JPanel buildHeader() {
        JPanel bar = new JPanel(new BorderLayout());
        bar.setBorder(new CompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0,
                UIManager.getColor("Separator.foreground")),
            BorderFactory.createEmptyBorder(8, 14, 8, 14)));

        // Left: title
        JLabel title = new JLabel("COOOKIES");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 15f));
        bar.add(title, BorderLayout.WEST);

        // Right: action buttons + toggles
        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        right.setOpaque(false);

        JButton execBtn = new JButton("▶  Execute Pipeline");
        execBtn.setFont(execBtn.getFont().deriveFont(Font.BOLD, 12f));
        execBtn.setFocusPainted(false);
        execBtn.addActionListener(e -> executePipeline());

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

        interceptionResToggle = new JToggleButton("Resp Detect: OFF");
        interceptionResToggle.setFont(interceptionResToggle.getFont().deriveFont(Font.BOLD, 11f));
        interceptionResToggle.setFocusPainted(false);
        interceptionResToggle.addActionListener(e -> {
            interceptionResEnabled = interceptionResToggle.isSelected();
            interceptionResToggle.setText("Resp Detect: " + (interceptionResEnabled ? "ON" : "OFF"));
            interceptionResToggle.setBackground(interceptionResEnabled ? new Color(144, 238, 144) : null);
        });

        right.add(interceptionToggle);
        right.add(ContentLengthToggle);
        right.add(interceptionResToggle);
        right.add(sep1);
        right.add(importBtn);
        right.add(exportBtn);
        right.add(saveBtn);
        right.add(sep2);
        right.add(execBtn);

        bar.add(right, BorderLayout.EAST);
        return bar;
    }

    private void setInterception(boolean enabled) {
        interceptionEnabled = enabled;
        interceptionToggle.setSelected(enabled);
        interceptionToggle.setText("Req Intercept: " + (enabled ? "ON" : "OFF"));
        interceptionToggle.setBackground(enabled ? new Color(144, 238, 144) : null);
    }

    /** Main area: pipeline list + editors on the left, config tabs on the right */
    private JComponent buildCenter() {
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        split.setResizeWeight(0.65);
        split.setBorder(null);
        split.setLeftComponent(buildPipelinePane());
        split.setRightComponent(buildRightTabs());
        return split;
    }

    /** Left side: pipeline list above, request/response editors below */
    private JComponent buildPipelinePane() {
        // --- Pipeline list with controls ---
        requestListModel = new DefaultListModel<>();
        requestList = new JList<>(requestListModel);
        requestList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        requestList.setCellRenderer(new DefaultListCellRenderer() {
            @Override public Component getListCellRendererComponent(
                    JList<?> list, Object value, int index,
                    boolean isSelected, boolean cellHasFocus) {
                Component c = super.getListCellRendererComponent(
                    list, value, index, isSelected, cellHasFocus);
                if (!isSelected && index == pipelineActiveReqRow) {
                    c.setBackground(new Color(128, 0, 128));
                    c.setForeground(new Color(255, 215, 0));
                }
                return c;
            }
        });
        requestList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                selectedRequestIndex = requestList.getSelectedIndex();
                loadSelectedRequest();
            }
        });

        JScrollPane listScroll = new JScrollPane(requestList);

        JButton addBtn    = new JButton("Add");
        JButton removeBtn = new JButton("Remove");
        JButton upBtn     = new JButton("↑");
        JButton downBtn   = new JButton("↓");
        JButton saveReqBtn = new JButton("Save Request");

        addBtn.addActionListener(e -> addNewRequest());
        removeBtn.addActionListener(e -> removeSelectedRequest());
        upBtn.addActionListener(e -> moveRequest(-1));
        downBtn.addActionListener(e -> moveRequest(1));
        saveReqBtn.addActionListener(e -> autoSaveRequest());

        JPanel listBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        listBtns.add(addBtn); listBtns.add(removeBtn);
        listBtns.add(upBtn);  listBtns.add(downBtn);
        listBtns.add(saveReqBtn);

        JPanel listPanel = new JPanel(new BorderLayout(0, 2));
        listPanel.setBorder(BorderFactory.createTitledBorder("Pipeline"));
        listPanel.add(listScroll, BorderLayout.CENTER);
        listPanel.add(listBtns,  BorderLayout.SOUTH);
        listPanel.setPreferredSize(new Dimension(0, 150));

        // --- Request and Response editors always visible, split vertically ---
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

        // Combine: list on top, both editors share remaining space
        JSplitPane left = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        left.setResizeWeight(0.18);
        left.setBorder(null);
        left.setTopComponent(listPanel);
        left.setBottomComponent(editorSplit);
        return left;
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

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        btns.add(addExtBtn); btns.add(addAuthBtn); btns.add(hint);

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

        // HTTP Config
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

        // Expiration strings
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

        // Execute Pipeline Hotkey
        JPanel hotkeySection = new JPanel();
        hotkeySection.setLayout(new BoxLayout(hotkeySection, BoxLayout.Y_AXIS));
        hotkeySection.setBorder(BorderFactory.createTitledBorder("Execute Pipeline Hotkey"));
        hotkeySection.setAlignmentX(Component.LEFT_ALIGNMENT);
        hotkeySection.setMaximumSize(new Dimension(Integer.MAX_VALUE, 90));

        executePipelineHotkeyField = new JTextField(executePipelineHotkey, 20);
        executePipelineHotkeyField.setFont(new Font("Monospaced", Font.PLAIN, 12));
        executePipelineHotkeyField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 25));

        JButton applyHotkeyBtn = new JButton("Apply");
        applyHotkeyBtn.setFocusPainted(false);
        applyHotkeyBtn.addActionListener(e -> {
            String newHotkey = executePipelineHotkeyField.getText().trim();
            if (newHotkey.isEmpty()) return;
            executePipelineHotkey = newHotkey;
            JOptionPane.showMessageDialog(mainPanel,
                "Hotkey updated to: " + newHotkey + "\n\nReload the extension in Burp to apply.",
                "Hotkey Updated", JOptionPane.INFORMATION_MESSAGE);
        });

        JLabel hotkeyNote = new JLabel("  Format: Ctrl+Shift+Equals  |  Reload extension to apply changes");
        hotkeyNote.setFont(hotkeyNote.getFont().deriveFont(Font.ITALIC, 10f));
        hotkeyNote.setForeground(new Color(120, 120, 120));

        JPanel hotkeyRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        hotkeyRow.add(new JLabel("Hotkey:"));
        hotkeyRow.add(executePipelineHotkeyField);
        hotkeyRow.add(applyHotkeyBtn);
        hotkeySection.add(hotkeyRow);
        hotkeySection.add(hotkeyNote);

        panel.add(httpSection);
        panel.add(Box.createVerticalStrut(12));
        panel.add(hotkeySection);
        panel.add(Box.createVerticalStrut(12));
        panel.add(expSection);
        return panel;
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
            // Invalid port
        }
    }

    private void addNewRequest() {
        String name = JOptionPane.showInputDialog(mainPanel, "Enter request name:");
        if (name != null && !name.trim().isEmpty()) {
            PipelineRequest req = new PipelineRequest(name.trim());
            req.rawRequest = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
            pipeline.add(req);
            requestListModel.addElement(req);
            requestList.setSelectedIndex(requestListModel.getSize() - 1);
        }
    }
    
    private void removeSelectedRequest() {
        int idx = requestList.getSelectedIndex();
        if (idx >= 0) {
            pipeline.remove(idx);
            requestListModel.remove(idx);
            if (requestListModel.getSize() > 0) {
                requestList.setSelectedIndex(Math.min(idx, requestListModel.getSize() - 1));
            } else {
                extractionPanel.removeAll();
                extractionPanel.revalidate();
                extractionPanel.repaint();
            }
        }
    }
    
    private void moveRequest(int direction) {
        int idx = requestList.getSelectedIndex();
        if (idx < 0) return;
        
        int newIdx = idx + direction;
        if (newIdx < 0 || newIdx >= requestListModel.getSize()) return;
        
        PipelineRequest req = pipeline.remove(idx);
        pipeline.add(newIdx, req);
        
        requestListModel.remove(idx);
        requestListModel.add(newIdx, req);
        requestList.setSelectedIndex(newIdx);
    }
    
    private void loadSelectedRequest() {
        int idx = requestList.getSelectedIndex();
        if (idx >= 0 && idx < pipeline.size()) {
            PipelineRequest req = pipeline.get(idx);
            rawRequestEditor.setRequest(HttpRequest.httpRequest(req.rawRequest));
            
            if (req.lastResponse != null && !req.lastResponse.isEmpty()) {
                rawResponseEditor.setResponse(HttpResponse.httpResponse(req.lastResponse));
            } else {
                rawResponseEditor.setResponse(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n"));
            }

            extractionPanel.removeAll();

            PipelineRequest authOwner = null;
            for (PipelineRequest pipeReq : pipeline) {
                if (pipeReq.authExtraction != null) {
                    authOwner = pipeReq;
                    break;
                }
            }

            if (authOwner == req && req.authExtraction != null) {
                extractionPanel.add(createAuthExtractionUI(req.authExtraction));
            }

            for (Extraction ext : req.extractions) {
                extractionPanel.add(createExtractionUI(ext));
            }
            
            extractionPanel.revalidate();
            extractionPanel.repaint();
            
            updateAvailableVariables();
        }
    }
    
    private void autoSaveRequest() {
        int idx = requestList.getSelectedIndex();
        if (idx >= 0 && idx < pipeline.size()) {
            HttpRequest request = rawRequestEditor.getRequest();
            if (request != null) {
                pipeline.get(idx).rawRequest = request.toString();
            }
        }
    }

    private void updateAvailableVariables() {
        int idx = requestList.getSelectedIndex();
        
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
        
        if (idx < 0) {
            sb.append("From previous requests:\n  (select a request)");
            availableVarsArea.setText(sb.toString());
            return;
        }
        
        sb.append("From previous requests:\n");
        boolean hasExtracted = false;
        for (int i = 0; i < idx; i++) {
            PipelineRequest prevReq = pipeline.get(i);
            for (Extraction ext : prevReq.extractions) {
                sb.append("  <COOOKIES:").append(ext.name).append(">\n");
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
        
        String name = JOptionPane.showInputDialog(mainPanel, "Enter unique extraction name:");
        if (name == null || name.trim().isEmpty()) return;
        
        PipelineRequest req = pipeline.get(idx);
        for (Extraction ext : req.extractions) {
            if (ext.name.equals(name.trim())) {
                JOptionPane.showMessageDialog(mainPanel, "Name already exists!");
                return;
            }
        }
        
        Extraction ext = new Extraction(name.trim());
        req.extractions.add(ext);
        extractionPanel.add(createExtractionUI(ext));
        extractionPanel.revalidate();
        extractionPanel.repaint();
        updateAvailableVariables();
    }
    
    private void addAuthExtraction() {
        int idx = requestList.getSelectedIndex();
        if (idx < 0) {
            JOptionPane.showMessageDialog(mainPanel, "Please select a request first.");
            return;
        }
        
        for (PipelineRequest req : pipeline) {
            if (req.authExtraction != null) {
                JOptionPane.showMessageDialog(mainPanel, 
                    "Auth extraction already exists in request: " + req.name + "\n" +
                    "Only one auth extraction allowed per pipeline.",
                    "Auth Extraction Exists", 
                    JOptionPane.WARNING_MESSAGE);
                return;
            }
        }
        
        PipelineRequest req = pipeline.get(idx);
        req.authExtraction = new AuthExtraction();
        
        extractionPanel.removeAll();
        extractionPanel.add(createAuthExtractionUI(req.authExtraction));
        
        for (Extraction ext : req.extractions) {
            extractionPanel.add(createExtractionUI(ext));
        }
        
        extractionPanel.revalidate();
        extractionPanel.repaint();
        updateAvailableVariables();
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
                pipeline.get(idx).extractions.remove(ext);
                extractionPanel.remove(panel);
                extractionPanel.revalidate();
                extractionPanel.repaint();
                updateAvailableVariables();
            }
        });

        helpMeBtn.addActionListener(e -> {
            String lastResponse = "";
            int idx = requestList.getSelectedIndex();
            if (idx >= 0 && idx < pipeline.size()) lastResponse = pipeline.get(idx).lastResponse;
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
    
    private JPanel createAuthExtractionUI(AuthExtraction authExt) {
        JPanel panel = new JPanel(new BorderLayout());
        
        TitledBorder border = BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(new Color(70, 130, 180), 2),
            "⭐ FINAL AUTH VALUE",
            TitledBorder.LEFT,
            TitledBorder.TOP,
            new Font("Dialog", Font.BOLD, 12),
            new Color(70, 130, 180)
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
                pipeline.get(idx).authExtraction = null;
                extractionPanel.remove(panel);
                extractionPanel.revalidate();
                extractionPanel.repaint();
                updateAvailableVariables();
            }
        });

        helpMeBtn.addActionListener(e -> {
            String lastResponse = "";
            int idx = requestList.getSelectedIndex();
            if (idx >= 0 && idx < pipeline.size()) lastResponse = pipeline.get(idx).lastResponse;
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

        JLabel infoLabel = new JLabel("Stored as: &lt;__COOOKIES__:USERNAME&gt;");
        infoLabel.setFont(new Font("Dialog", Font.PLAIN, 10));
        infoLabel.setForeground(new Color(70, 130, 180));
        
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

    // ── Regex Helper Dialog ────────────────────────────────────────────────────
    private void showRegexHelper(JTextField targetValueField, String initialResponse) {
        JFrame ownerFrame = new JFrame();
        ownerFrame.setUndecorated(true);
        ownerFrame.setVisible(true);
        ownerFrame.setLocation(-1, -1);
        ownerFrame.setSize(0, 0);

        JDialog dialog = new JDialog(ownerFrame,
            "Regex Builder", java.awt.Dialog.ModalityType.MODELESS);
        dialog.setSize(800, 600);
        dialog.setLocationRelativeTo(mainPanel);

        dialog.addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosed(java.awt.event.WindowEvent e) {
                ownerFrame.dispose();
            }
        });

        dialog.setLayout(new BorderLayout(0, 0));

        // ── Top: instructions ──
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

        // ── Center split: response text (top) + result area (bottom) ──
        JTextArea responseArea = new JTextArea();
        responseArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        responseArea.setLineWrap(false);
        JScrollPane responseScroll = new JScrollPane(responseArea);
        responseScroll.setBorder(BorderFactory.createTitledBorder("Sample Response"));

        // Result area
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

        // ── Bottom buttons ──
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

        // ── Populate initial response ──
        if (!initialResponse.isEmpty()) {
            responseArea.setText(initialResponse);
        } else {
            responseArea.setText("(No response yet — paste a sample here)");
            responseArea.selectAll();
        }

        // ── Actions ──
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
            // Auto-test immediately
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

        // Live test as pattern is edited
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
        // ── Escape any regex metacharacters in the selected value ──
        String escapedValue = java.util.regex.Pattern.quote(selected);

        // ── Scan left for an anchor (up to 60 chars) ──
        int leftScan   = Math.max(0, selStart - 60);
        String leftCtx = text.substring(leftScan, selStart);

        // ── Scan right for a closing delimiter (up to 60 chars) ──
        int rightScan   = Math.min(text.length(), selEnd + 60);
        String rightCtx = text.substring(selEnd, rightScan);

        // Determine left anchor: last meaningful delimiter before the selection
        char leftDelim  = findLeftDelimiter(leftCtx);
        char rightDelim = findRightDelimiter(rightCtx, leftDelim);

        // Build the capture group character class based on the closing delimiter
        String captureClass = buildCaptureClass(leftDelim, rightDelim);

        // Build literal anchors (escaped for regex)
        String leftAnchorStr  = leftDelim  != 0 ? java.util.regex.Pattern.quote(String.valueOf(leftDelim))  : null;
        String rightAnchorStr = rightDelim != 0 ? java.util.regex.Pattern.quote(String.valueOf(rightDelim)) : null;

        // Prefer a short literal left-anchor string rather than just the delimiter char
        // for more specificity (e.g. `"token":"`  instead of just `"`)
        String leftLiteral  = buildLeftLiteral(leftCtx,  leftDelim);
        String rightLiteral = buildRightLiteral(rightCtx, rightDelim);

        if (leftLiteral != null && rightLiteral != null) {
            return leftLiteral + "(" + captureClass + ")" + rightLiteral;
        } else if (leftLiteral != null) {
            return leftLiteral + "(" + captureClass + ")";
        } else if (rightLiteral != null) {
            return "(" + captureClass + ")" + rightLiteral;
        } else {
            // Fallback: just wrap the escaped selection in a group
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
        // If left was a quote-type, match it first
        if (leftDelim == '"' || leftDelim == '\'' || leftDelim == '`') {
            if (rightCtx.indexOf(leftDelim) >= 0) return leftDelim;
        }
        // Otherwise scan for common closers
        char[] closers = {'"', '\'', '<', '>', '}', ']', ')', ';', ',', ' ', '\n', '\r'};
        for (int i = 0; i < rightCtx.length(); i++) {
            char c = rightCtx.charAt(i);
            for (char cl : closers) if (c == cl) return c;
        }
        return 0;
    }

    /** Builds the regex character class for the capture group. */
    private String buildCaptureClass(char leftDelim, char rightDelim) {
        // Use the right delimiter as the exclusion boundary if available, else left
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
        // Take from up to 8 chars before the delimiter to the delimiter (inclusive)
        int start = Math.max(0, delimPos - 8);
        String raw = leftCtx.substring(start, delimPos + 1);
        // Only keep the last "meaningful" chunk (no newlines)
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
        // Take the delimiter plus up to 4 chars after for specificity
        int end = Math.min(rightCtx.length(), delimPos + 5);
        String raw = rightCtx.substring(delimPos, end);
        int nl = raw.indexOf('\n');
        int cr = raw.indexOf('\r');
        int cut = nl >= 0 && cr >= 0 ? Math.min(nl, cr) : Math.max(nl, cr);
        if (cut >= 0) raw = raw.substring(0, cut);
        // Trim to just the delimiter if the rest is purely alphanumeric (too generic as anchor)
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
                
                pipeline.clear();
                requestListModel.clear();
                credentialsTableModel.setRowCount(0);
                staticVarsTableModel.setRowCount(0);
                extractionPanel.removeAll();
                extractionPanel.revalidate();
                extractionPanel.repaint();
                clearEditorsForImport();
                
                int reqsStart = json.indexOf("\"requests\"");
                int reqsArrayStart = json.indexOf("[", reqsStart);
                int reqsArrayEnd = findMatchingBracket(json, reqsArrayStart);
                String requestsSection = json.substring(reqsArrayStart + 1, reqsArrayEnd);
                
                String[] requestBlocks = splitJsonObjects(requestsSection);
                for (String reqBlock : requestBlocks) {
                    if (reqBlock.trim().isEmpty()) continue;
                    
                    String name = extractJsonString(reqBlock, "name");
                    String rawRequest = extractJsonString(reqBlock, "rawRequest");
                    
                    PipelineRequest req = new PipelineRequest(name);
                    req.rawRequest = rawRequest;
                    
                    int authExtStart = reqBlock.indexOf("\"authExtraction\"");
                    if (authExtStart != -1) {
                        int colonAfterAuth = reqBlock.indexOf(":", authExtStart);
                        int nextCommaOrBrace = reqBlock.indexOf(",", colonAfterAuth);
                        if (nextCommaOrBrace == -1) {
                            nextCommaOrBrace = reqBlock.indexOf("}", colonAfterAuth);
                        }
                        String authValue = reqBlock.substring(colonAfterAuth + 1, nextCommaOrBrace).trim();
                        
                        if (!authValue.startsWith("null")) {
                            int authObjStart = reqBlock.indexOf("{", authExtStart);
                            if (authObjStart != -1 && authObjStart < nextCommaOrBrace) {
                                int authObjEnd = findMatchingBracket(reqBlock, authObjStart);
                                String authBlock = reqBlock.substring(authObjStart, authObjEnd + 1);
                                
                                AuthExtraction authExt = new AuthExtraction();
                                authExt.type = extractJsonInt(authBlock, "type");
                                authExt.value = extractJsonString(authBlock, "value");
                                req.authExtraction = authExt;
                            }
                        }
                    }
                    
                    int extStart = reqBlock.indexOf("\"extractions\"");
                    if (extStart != -1) {
                        int extArrayStart = reqBlock.indexOf("[", extStart);
                        int extArrayEnd = findMatchingBracket(reqBlock, extArrayStart);
                        String extractionsSection = reqBlock.substring(extArrayStart + 1, extArrayEnd);
                        
                        String[] extBlocks = splitJsonObjects(extractionsSection);
                        for (String extBlock : extBlocks) {
                            if (extBlock.trim().isEmpty()) continue;
                            
                            String extName = extractJsonString(extBlock, "name");
                            int extType = extractJsonInt(extBlock, "type");
                            String extValue = extractJsonString(extBlock, "value");
                            
                            Extraction ext = new Extraction(extName);
                            ext.type = extType;
                            ext.value = extValue;
                            req.extractions.add(ext);
                        }
                    }
                    
                    pipeline.add(req);
                    requestListModel.addElement(req);
                }
                
                int credsStart = json.indexOf("\"credentials\"");
                if (credsStart != -1) {
                    int credsArrayStart = json.indexOf("[", credsStart);
                    int credsArrayEnd = findMatchingBracket(json, credsArrayStart);
                    String credsSection = json.substring(credsArrayStart + 1, credsArrayEnd);
                    
                    String[] credBlocks = splitJsonObjects(credsSection);
                    for (String credBlock : credBlocks) {
                        if (credBlock.trim().isEmpty()) continue;
                        
                        String username = extractJsonString(credBlock, "username");
                        String password = extractJsonString(credBlock, "password");
                        credentialsTableModel.addRow(new Object[]{username, password});
                    }
                }
                
                int varsStart = json.indexOf("\"staticVariables\"");
                if (varsStart != -1) {
                    int varsArrayStart = json.indexOf("[", varsStart);
                    int varsArrayEnd = findMatchingBracket(json, varsArrayStart);
                    String varsSection = json.substring(varsArrayStart + 1, varsArrayEnd);
                    
                    String[] varBlocks = splitJsonObjects(varsSection);
                    for (String varBlock : varBlocks) {
                        if (varBlock.trim().isEmpty()) continue;
                        
                        String varName = extractJsonString(varBlock, "name");
                        String varValue = extractJsonString(varBlock, "value");
                        staticVarsTableModel.addRow(new Object[]{varName, varValue});
                    }
                }
                
                int expStart = json.indexOf("\"expirationStrings\"");
                if (expStart != -1) {
                    int expArrayStart = json.indexOf("[", expStart);
                    int expArrayEnd = findMatchingBracket(json, expArrayStart);
                    String expSection = json.substring(expArrayStart + 1, expArrayEnd);
                    
                    StringBuilder expText = new StringBuilder();
                    int currentPos = 0;
                    while (currentPos < expSection.length()) {
                        int quoteStart = expSection.indexOf("\"", currentPos);
                        if (quoteStart == -1) break;
                        
                        int quoteEnd = quoteStart + 1;
                        while (quoteEnd < expSection.length()) {
                            if (expSection.charAt(quoteEnd) == '\"' && expSection.charAt(quoteEnd - 1) != '\\') {
                                break;
                            }
                            quoteEnd++;
                        }
                        
                        if (quoteEnd < expSection.length()) {
                            String expString = unescapeJson(expSection.substring(quoteStart + 1, quoteEnd));
                            if (expText.length() > 0) {
                                expText.append("\n");
                            }
                            expText.append(expString);
                        }
                        
                        currentPos = quoteEnd + 1;
                    }
                    
                    expirationStringsArea.setText(expText.toString());
                    updateExpirationStringsList();
                }
                
                int configStart = json.indexOf("\"httpConfig\"");
                if (configStart != -1) {
                    int configObjStart = json.indexOf("{", configStart);
                    if (configObjStart != -1) {
                        int configObjEnd = findMatchingBracket(json, configObjStart);
                        String configBlock = json.substring(configObjStart, configObjEnd + 1);
                        
                        configuredPort = extractJsonInt(configBlock, "port");
                        
                        int httpsKeyIndex = configBlock.indexOf("\"https\"");
                        if (httpsKeyIndex != -1) {
                            int colonIndex = configBlock.indexOf(":", httpsKeyIndex);
                            int valueStart = colonIndex + 1;
                            while (valueStart < configBlock.length() && Character.isWhitespace(configBlock.charAt(valueStart))) {
                                valueStart++;
                            }
                            configuredHttps = configBlock.substring(valueStart).trim().startsWith("true");
                        }
                        
                        defaultPortField.setText(String.valueOf(configuredPort));
                        forceHttpsCheckbox.setSelected(configuredHttps);
                    }
                }
                
                if (requestListModel.getSize() > 0) {
                    requestList.setSelectedIndex(0);
                    loadSelectedRequest();
                }
                
                updateAvailableVariables();
                
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

                // Persist the freshly imported config into the project file
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

    private int findMatchingBracket(String s, int start) {
        int depth = 1;
        int i = start + 1;
        while (i < s.length() && depth > 0) {
            if (s.charAt(i) == '[' || s.charAt(i) == '{') depth++;
            if (s.charAt(i) == ']' || s.charAt(i) == '}') depth--;
            i++;
        }
        return i - 1;
    }

    private String[] splitJsonObjects(String s) {
        List<String> objects = new ArrayList<>();
        int depth = 0;
        int start = 0;
        
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '{' || c == '[') depth++;
            if (c == '}' || c == ']') depth--;
            
            if (c == ',' && depth == 0) {
                objects.add(s.substring(start, i));
                start = i + 1;
            }
        }
        
        if (start < s.length()) {
            objects.add(s.substring(start));
        }
        
        return objects.toArray(new String[0]);
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
                        // Found the exact tab that holds our panel
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

    private void setStatus(String text, Color color) {
        SwingUtilities.invokeLater(() -> {
            if (statusLabel != null) {
                statusLabel.setText(text);
                statusLabel.setForeground(color != null ? color
                    : UIManager.getColor("Label.disabledForeground"));
            }
        });
    }

    private void executePipeline() {
        finalAuthValues.clear();
        autoSaveRequest();
        
        new Thread(() -> {
            try {
                executePipelineInBackground();
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
    
    private void executePipelineInBackground() {
        SwingUtilities.invokeLater(() -> {
            logArea.setText("");
            log("=== Starting Pipeline Execution ===\n");
            setStatus("▶ Running…", new Color(30, 140, 30));
            setTabColor(new Color(128, 0, 128), new Color(255, 215, 0));
        });
        
        List<String[]> credList = new ArrayList<>();
        
        for (int i = 0; i < credentialsTableModel.getRowCount(); i++) {
            String username = (String) credentialsTableModel.getValueAt(i, 0);
            String password = (String) credentialsTableModel.getValueAt(i, 1);
            if (username != null && password != null && !username.trim().isEmpty()) {
                credList.add(new String[]{username.trim(), password.trim()});
            }
        }
        
        if (credList.isEmpty()) {
            SwingUtilities.invokeLater(() -> {
                showError("No valid credentials provided. Use format: username:password");
                setStatus("Ready", UIManager.getColor("Label.disabledForeground"));
                setTabColor(null, null);
            });
            return;
        }
        
        final int totalCreds = credList.size();
        int successCount = 0;
        int failCount = 0;

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
            
            for (int j = 0; j < staticVarsTableModel.getRowCount(); j++) {
                String varName = (String) staticVarsTableModel.getValueAt(j, 0);
                String varValue = (String) staticVarsTableModel.getValueAt(j, 1);
                if (varName != null && !varName.trim().isEmpty() && varValue != null) {
                    variables.put(varName.trim(), varValue);
                    log("  Static var '" + varName.trim() + "': " + 
                        (varValue.length() > 50 ? varValue.substring(0, 50) + "..." : varValue));
                }
            }
            
            try {
                final int credIdx = i;
                final String credUser = cred[0];
                final int total = credList.size();
                setStatus("▶ Running · User " + (credIdx+1) + "/" + total + " (" + credUser + ") · Step 0/" + pipeline.size(), new Color(30, 140, 30));
                executePipelineForCredential(variables, cred[0]);
                log("✓ Pipeline completed successfully for " + cred[0]);
                successCount++;
            } catch (Exception e) {
                log("✗ Pipeline failed for " + cred[0] + ": " + e.getMessage());
                final String errorMsg = "Pipeline failed for " + cred[0] + ":\n\n" + e.getMessage() + 
                         "\n\nStack trace:\n" + getStackTrace(e);
                SwingUtilities.invokeLater(() -> showError(errorMsg));
                failCount++;
            }
        }

        final int finalSuccess = successCount;
        final int finalFail = failCount;
        SwingUtilities.invokeLater(() -> {
            pipelineActiveCredRow = -1;
            pipelineActiveReqRow  = -1;
            credentialsTable.repaint();
            requestList.repaint();
            String summary = "✔ Done · " + finalSuccess + "/" + totalCreds + " users ok";
            if (finalFail > 0) summary += " · " + finalFail + " failed";
            setStatus(summary, finalFail > 0 ? new Color(180, 50, 50) : new Color(30, 140, 30));
            setTabColor(null, null);
        });
        
        log("\n=== Pipeline Execution Complete ===");
        saveToProject();
    }
    
    private void executePipelineForCredential(Map<String, String> variables, String username) throws Exception {
        String allCookies = "";
        
        if (!extractedValues.containsKey(username)) {
            extractedValues.put(username, new HashMap<>());
        }
        Map<String, String> userVars = extractedValues.get(username);
        
        for (int i = 0; i < pipeline.size(); i++) {
            PipelineRequest req = pipeline.get(i);
            log("\n  Request " + (i + 1) + ": " + req.name);
            final int stepIdx = i;
            final String stepUser = username;
            final int totalSteps = pipeline.size();
            final int totalCreds2 = credentialsTableModel.getRowCount();
            SwingUtilities.invokeLater(() -> {
                pipelineActiveReqRow = stepIdx;
                requestList.repaint();
                // find cred row index for this username
                for (int ci = 0; ci < credentialsTableModel.getRowCount(); ci++) {
                    if (stepUser.equals(credentialsTableModel.getValueAt(ci, 0))) {
                        pipelineActiveCredRow = ci;
                        break;
                    }
                }
                credentialsTable.repaint();
                setStatus("▶ Running · User " + (pipelineActiveCredRow+1) + "/" + totalCreds2
                    + " (" + stepUser + ") · Step " + (stepIdx+1) + "/" + totalSteps
                    + " (" + req.name + ")", new Color(30, 140, 30));
            });
            
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
            port = configuredPort;
            
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
            
            final int currentIdx = i;
            SwingUtilities.invokeLater(() -> {
                if (requestList.getSelectedIndex() == currentIdx) {
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
                } else {
                    log("    Warning: Auth extraction failed");
                }
            }
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
    
    private String extractJsonValue(String json, String path) {
        try {
            String current = json.trim();
            String[] parts = path.replaceAll("\\[|\\]", " ").split("'");
            
            for (String part : parts) {
                part = part.trim();
                if (part.isEmpty()) continue;
                
                String searchKey = "\"" + part + "\"";
                int keyIndex = current.indexOf(searchKey);
                if (keyIndex == -1) return null;
                
                int colonIndex = current.indexOf(":", keyIndex);
                if (colonIndex == -1) return null;
                
                int valueStart = colonIndex + 1;
                while (valueStart < current.length() && Character.isWhitespace(current.charAt(valueStart))) {
                    valueStart++;
                }
                
                if (current.charAt(valueStart) == '"') {
                    int valueEnd = current.indexOf('"', valueStart + 1);
                    return current.substring(valueStart + 1, valueEnd);
                } else if (current.charAt(valueStart) == '{') {
                    int depth = 1;
                    int valueEnd = valueStart + 1;
                    while (depth > 0 && valueEnd < current.length()) {
                        if (current.charAt(valueEnd) == '{') depth++;
                        if (current.charAt(valueEnd) == '}') depth--;
                        valueEnd++;
                    }
                    current = current.substring(valueStart, valueEnd);
                } else {
                    int valueEnd = valueStart;
                    while (valueEnd < current.length() && 
                           current.charAt(valueEnd) != ',' && 
                           current.charAt(valueEnd) != '}') {
                        valueEnd++;
                    }
                    return current.substring(valueStart, valueEnd).trim();
                }
            }
            
            return current;
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
        SwingUtilities.invokeLater(() -> {
            logArea.append(message + "\n");
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

            pipeline.clear();
            requestListModel.clear();
            credentialsTableModel.setRowCount(0);
            staticVarsTableModel.setRowCount(0);
            extractionPanel.removeAll();
            extractionPanel.revalidate();
            extractionPanel.repaint();
            clearEditorsForImport();

            // --- requests ---
            int reqsStart = json.indexOf("\"requests\"");
            if (reqsStart != -1) {
                int reqsArrayStart = json.indexOf("[", reqsStart);
                int reqsArrayEnd = findMatchingBracket(json, reqsArrayStart);
                String requestsSection = json.substring(reqsArrayStart + 1, reqsArrayEnd);
                String[] requestBlocks = splitJsonObjects(requestsSection);
                for (String reqBlock : requestBlocks) {
                    if (reqBlock.trim().isEmpty()) continue;
                    String name = extractJsonString(reqBlock, "name");
                    String rawRequest = extractJsonString(reqBlock, "rawRequest");
                    PipelineRequest req = new PipelineRequest(name);
                    req.rawRequest = rawRequest;

                    int authExtStart = reqBlock.indexOf("\"authExtraction\"");
                    if (authExtStart != -1) {
                        int colonAfterAuth = reqBlock.indexOf(":", authExtStart);
                        int nextCommaOrBrace = reqBlock.indexOf(",", colonAfterAuth);
                        if (nextCommaOrBrace == -1) nextCommaOrBrace = reqBlock.indexOf("}", colonAfterAuth);
                        String authValue = reqBlock.substring(colonAfterAuth + 1, nextCommaOrBrace).trim();
                        if (!authValue.startsWith("null")) {
                            int authObjStart = reqBlock.indexOf("{", authExtStart);
                            if (authObjStart != -1 && authObjStart < nextCommaOrBrace) {
                                int authObjEnd = findMatchingBracket(reqBlock, authObjStart);
                                String authBlock = reqBlock.substring(authObjStart, authObjEnd + 1);
                                AuthExtraction authExt = new AuthExtraction();
                                authExt.type = extractJsonInt(authBlock, "type");
                                authExt.value = extractJsonString(authBlock, "value");
                                req.authExtraction = authExt;
                            }
                        }
                    }

                    int extStart = reqBlock.indexOf("\"extractions\"");
                    if (extStart != -1) {
                        int extArrayStart = reqBlock.indexOf("[", extStart);
                        int extArrayEnd = findMatchingBracket(reqBlock, extArrayStart);
                        String extractionsSection = reqBlock.substring(extArrayStart + 1, extArrayEnd);
                        String[] extBlocks = splitJsonObjects(extractionsSection);
                        for (String extBlock : extBlocks) {
                            if (extBlock.trim().isEmpty()) continue;
                            String extName = extractJsonString(extBlock, "name");
                            int extType = extractJsonInt(extBlock, "type");
                            String extValue = extractJsonString(extBlock, "value");
                            Extraction ext = new Extraction(extName);
                            ext.type = extType;
                            ext.value = extValue;
                            req.extractions.add(ext);
                        }
                    }

                    pipeline.add(req);
                    requestListModel.addElement(req);
                }
            }

            // --- credentials ---
            int credsStart = json.indexOf("\"credentials\"");
            if (credsStart != -1) {
                int credsArrayStart = json.indexOf("[", credsStart);
                int credsArrayEnd = findMatchingBracket(json, credsArrayStart);
                String credsSection = json.substring(credsArrayStart + 1, credsArrayEnd);
                String[] credBlocks = splitJsonObjects(credsSection);
                for (String credBlock : credBlocks) {
                    if (credBlock.trim().isEmpty()) continue;
                    String username = extractJsonString(credBlock, "username");
                    String password = extractJsonString(credBlock, "password");
                    credentialsTableModel.addRow(new Object[]{username, password});
                }
            }

            // --- static variables ---
            int varsStart = json.indexOf("\"staticVariables\"");
            if (varsStart != -1) {
                int varsArrayStart = json.indexOf("[", varsStart);
                int varsArrayEnd = findMatchingBracket(json, varsArrayStart);
                String varsSection = json.substring(varsArrayStart + 1, varsArrayEnd);
                String[] varBlocks = splitJsonObjects(varsSection);
                for (String varBlock : varBlocks) {
                    if (varBlock.trim().isEmpty()) continue;
                    String varName = extractJsonString(varBlock, "name");
                    String varValue = extractJsonString(varBlock, "value");
                    staticVarsTableModel.addRow(new Object[]{varName, varValue});
                }
            }

            // --- expiration strings ---
            int expStart = json.indexOf("\"expirationStrings\"");
            if (expStart != -1) {
                int expArrayStart = json.indexOf("[", expStart);
                int expArrayEnd = findMatchingBracket(json, expArrayStart);
                String expSection = json.substring(expArrayStart + 1, expArrayEnd);
                StringBuilder expText = new StringBuilder();
                int currentPos = 0;
                while (currentPos < expSection.length()) {
                    int quoteStart = expSection.indexOf("\"", currentPos);
                    if (quoteStart == -1) break;
                    int quoteEnd = quoteStart + 1;
                    while (quoteEnd < expSection.length()) {
                        if (expSection.charAt(quoteEnd) == '\"' && expSection.charAt(quoteEnd - 1) != '\\') break;
                        quoteEnd++;
                    }
                    if (quoteEnd < expSection.length()) {
                        String expString = unescapeJson(expSection.substring(quoteStart + 1, quoteEnd));
                        if (expText.length() > 0) expText.append("\n");
                        expText.append(expString);
                    }
                    currentPos = quoteEnd + 1;
                }
                expirationStringsArea.setText(expText.toString());
                updateExpirationStringsList();
            }

            // --- httpConfig ---
            int configStart = json.indexOf("\"httpConfig\"");
            if (configStart != -1) {
                int configObjStart = json.indexOf("{", configStart);
                if (configObjStart != -1) {
                    int configObjEnd = findMatchingBracket(json, configObjStart);
                    String configBlock = json.substring(configObjStart, configObjEnd + 1);
                    configuredPort = extractJsonInt(configBlock, "port");
                    int httpsKeyIndex = configBlock.indexOf("\"https\"");
                    if (httpsKeyIndex != -1) {
                        int colonIndex = configBlock.indexOf(":", httpsKeyIndex);
                        int valueStart = colonIndex + 1;
                        while (valueStart < configBlock.length() && Character.isWhitespace(configBlock.charAt(valueStart))) valueStart++;
                        configuredHttps = configBlock.substring(valueStart).trim().startsWith("true");
                    }
                    defaultPortField.setText(String.valueOf(configuredPort));
                    forceHttpsCheckbox.setSelected(configuredHttps);
                }
            }

            // --- executePipelineHotkey ---
            int execHkStart = json.indexOf("\"executePipelineHotkey\"");
            if (execHkStart != -1) {
                int colonIdx = json.indexOf(":", execHkStart);
                int qStart   = json.indexOf("\"", colonIdx);
                int qEnd     = json.indexOf("\"", qStart + 1);
                if (qStart != -1 && qEnd > qStart) {
                    String savedHk = unescapeJson(json.substring(qStart + 1, qEnd));
                    if (!savedHk.trim().isEmpty()) {
                        executePipelineHotkey = savedHk.trim();
                        if (executePipelineHotkeyField != null)
                            executePipelineHotkeyField.setText(executePipelineHotkey);
                    }
                }
            }

            if (requestListModel.getSize() > 0) {
                requestList.setSelectedIndex(0);
                loadSelectedRequest();
            }

            updateAvailableVariables();
            api.logging().logToOutput("[COOOKIES] Configuration loaded from project: " +
                pipeline.size() + " requests, " +
                credentialsTableModel.getRowCount() + " credentials, " +
                staticVarsTableModel.getRowCount() + " static variables.");

        } catch (Exception e) {
            api.logging().logToError("[COOOKIES] Failed to load configuration from project: " + e.getMessage());
        }
    }

    private String buildJsonExport() {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        
        json.append("  \"requests\": [\n");
        for (int i = 0; i < pipeline.size(); i++) {
            PipelineRequest req = pipeline.get(i);
            json.append("    {\n");
            json.append("      \"name\": \"").append(escapeJson(req.name)).append("\",\n");
            json.append("      \"rawRequest\": \"").append(escapeJson(req.rawRequest)).append("\",\n");
            
            json.append("      \"authExtraction\": ");
            if (req.authExtraction != null) {
                json.append("{\n");
                json.append("        \"type\": ").append(req.authExtraction.type).append(",\n");
                json.append("        \"value\": \"").append(escapeJson(req.authExtraction.value)).append("\"\n");
                json.append("      },\n");
            } else {
                json.append("null,\n");
            }
            
            json.append("      \"extractions\": [\n");
            
            for (int j = 0; j < req.extractions.size(); j++) {
                Extraction ext = req.extractions.get(j);
                json.append("        {\n");
                json.append("          \"name\": \"").append(escapeJson(ext.name)).append("\",\n");
                json.append("          \"type\": ").append(ext.type).append(",\n");
                json.append("          \"value\": \"").append(escapeJson(ext.value)).append("\"\n");
                json.append("        }");
                if (j < req.extractions.size() - 1) json.append(",");
                json.append("\n");
            }
            
            json.append("      ]\n");
            json.append("    }");
            if (i < pipeline.size() - 1) json.append(",");
            json.append("\n");
        }
        json.append("  ],\n");
        
        json.append("  \"credentials\": [\n");
        for (int i = 0; i < credentialsTableModel.getRowCount(); i++) {
            String username = (String) credentialsTableModel.getValueAt(i, 0);
            String password = (String) credentialsTableModel.getValueAt(i, 1);
            if (username != null && password != null) {
                json.append("    {\"username\": \"").append(escapeJson(username)).append("\", ");
                json.append("\"password\": \"").append(escapeJson(password)).append("\"}");
                if (i < credentialsTableModel.getRowCount() - 1) json.append(",");
                json.append("\n");
            }
        }
        json.append("  ],\n");
        
        json.append("  \"staticVariables\": [\n");
        for (int i = 0; i < staticVarsTableModel.getRowCount(); i++) {
            String varName = (String) staticVarsTableModel.getValueAt(i, 0);
            String varValue = (String) staticVarsTableModel.getValueAt(i, 1);
            if (varName != null && varValue != null) {
                json.append("    {\"name\": \"").append(escapeJson(varName)).append("\", ");
                json.append("\"value\": \"").append(escapeJson(varValue)).append("\"}");
                if (i < staticVarsTableModel.getRowCount() - 1) json.append(",");
                json.append("\n");
            }
        }
        json.append("  ],\n");
        
        json.append("  \"expirationStrings\": [\n");
        updateExpirationStringsList();
        synchronized (expirationStrings) {
            for (int i = 0; i < expirationStrings.size(); i++) {
                json.append("    \"").append(escapeJson(expirationStrings.get(i))).append("\"");
                if (i < expirationStrings.size() - 1) json.append(",");
                json.append("\n");
            }
        }
        json.append("  ],\n");
        
        json.append("  \"httpConfig\": {\n");
        json.append("    \"port\": ").append(configuredPort).append(",\n");
        json.append("    \"https\": ").append(configuredHttps).append("\n");
        json.append("  },\n");
        json.append("  \"executePipelineHotkey\": \"").append(escapeJson(executePipelineHotkey)).append("\"\n");

        json.append("}");
        return json.toString();
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private String unescapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t")
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
    }

    private String extractJsonString(String json, String key) {
        String searchKey = "\"" + key + "\"";
        int keyIndex = json.indexOf(searchKey);
        if (keyIndex == -1) return null;
        
        int colonIndex = json.indexOf(":", keyIndex);
        int startQuote = json.indexOf("\"", colonIndex);
        int endQuote = startQuote + 1;
        
        while (endQuote < json.length()) {
            if (json.charAt(endQuote) == '\"' && json.charAt(endQuote - 1) != '\\') {
                break;
            }
            endQuote++;
        }
        
        return unescapeJson(json.substring(startQuote + 1, endQuote));
    }

    private int extractJsonInt(String json, String key) {
        String searchKey = "\"" + key + "\"";
        int keyIndex = json.indexOf(searchKey);
        if (keyIndex == -1) return 0;
        
        int colonIndex = json.indexOf(":", keyIndex);
        int numStart = colonIndex + 1;
        while (numStart < json.length() && Character.isWhitespace(json.charAt(numStart))) {
            numStart++;
        }
        
        int numEnd = numStart;
        while (numEnd < json.length() && Character.isDigit(json.charAt(numEnd))) {
            numEnd++;
        }
        
        return Integer.parseInt(json.substring(numStart, numEnd));
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
                InputStream stream = getClass().getResourceAsStream("/NANOWAR_OF_STEEL-HelloWorld.java.mp3");
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

    // ── Inner data classes ────────────────────────────────────────────────────
    class PipelineRequest {
        String name;
        String rawRequest;
        String lastResponse;
        List<Extraction> extractions;
        AuthExtraction authExtraction;
        
        PipelineRequest(String name) {
            this.name = name;
            this.rawRequest = "";
            this.lastResponse = null;
            this.extractions = new ArrayList<>();
            this.authExtraction = null;
        }
        
        @Override
        public String toString() {
            return name;
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