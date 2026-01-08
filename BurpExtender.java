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

public class BurpExtender implements BurpExtension, HttpHandler, ContextMenuItemsProvider {
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
    private Map<String, String> finalAuthValues;
    private boolean interceptionEnabled = false;
    private boolean interceptionResEnabled = false;
    private boolean proxyTool = false;
    private boolean proxyToolRes = false;
    private JToggleButton interceptionToggle;
    private JToggleButton interceptionResToggle;
    private JToggleButton proxyToggle;
    private JToggleButton proxyToggleRes;

    private JTextField defaultPortField;
    private JCheckBox forceHttpsCheckbox;
    private int configuredPort = 443;
    private boolean configuredHttps = true;

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
            .withDescription("IMPORTANT: after editing the Hotkey reload the extension to see changes")
            .withSettings(
                SettingsPanelSetting.stringSetting("Hotkey", "Ctrl+Shift+C")
                )
            .build();
        api.userInterface().registerSettingsPanel(panel);

        String preferredHotkey = panel.getString("Hotkey");

        api.logging().logToOutput("Hotkey loaded: "+preferredHotkey);

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
        
        SwingUtilities.invokeLater(() -> {
            mainPanel = new JPanel(new BorderLayout());
            
            rawRequestEditor = api.userInterface().createHttpRequestEditor();
            rawResponseEditor = api.userInterface().createHttpResponseEditor();
            
            JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
            mainSplit.setResizeWeight(0.4);
            
            JSplitPane topSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
            topSplit.setResizeWeight(0.7);
            topSplit.setLeftComponent(createTopLeftPanel());
            topSplit.setRightComponent(createTopRightPanel());
            
            JPanel middlePanel = createMiddlePanel();
            
            JSplitPane bottomSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
            bottomSplit.setResizeWeight(0.5);
            bottomSplit.setLeftComponent(createBottomLeftPanel());
            bottomSplit.setRightComponent(createBottomRightPanel());
            
            JPanel topWithMiddle = new JPanel(new BorderLayout());
            topWithMiddle.add(topSplit, BorderLayout.CENTER);
            topWithMiddle.add(middlePanel, BorderLayout.SOUTH);
            
            mainSplit.setTopComponent(topWithMiddle);
            mainSplit.setBottomComponent(bottomSplit);
            
            mainPanel.add(mainSplit);
            api.userInterface().registerSuiteTab("COOOKIES", mainPanel);
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
                
                String modifiedRequest = replacePatterns(requestStr);
                
                if (!modifiedRequest.equals(requestStr)) {
                    HttpRequest newRequest = HttpRequest.httpRequest(modifiedRequest);
                    
                    if (requestToBeSent.httpService() != null) {
                        newRequest = newRequest.withService(requestToBeSent.httpService());
                    }
                    
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
        if (interceptionResEnabled) {
            
            try {
                String responseStr = responseReceived.toString();

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
                        .withAddedHeader("### Coookies-Expiration", "HIT");
                    
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

        return ResponseReceivedAction.continueWith(responseReceived);
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

    private String replacePatterns(String request) {
        String result = request;
        
        Pattern authPattern = Pattern.compile("<__COOOKIES__:([^>]+)>");
        Matcher authMatcher = authPattern.matcher(result);
        StringBuffer sb = new StringBuffer();
        
        while (authMatcher.find()) {
            String username = authMatcher.group(1);
            String replacement = finalAuthValues.getOrDefault(username, authMatcher.group(0));
            authMatcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        authMatcher.appendTail(sb);
        result = sb.toString();
        
        Pattern varPattern = Pattern.compile("<COOOKIES:([^:>]+):([^>]+)>");
        Matcher varMatcher = varPattern.matcher(result);
        sb = new StringBuffer();
        
        while (varMatcher.find()) {
            String username = varMatcher.group(1);
            String varName = varMatcher.group(2);
            
            Map<String, String> userVars = extractedValues.get(username);
            String replacement = varMatcher.group(0);
            
            if (userVars != null && userVars.containsKey(varName)) {
                replacement = userVars.get(varName);
            }
            
            varMatcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        varMatcher.appendTail(sb);
        result = sb.toString();
        
        return result;
    }
    
    private JPanel createTopLeftPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Pipeline Requests"));
        
        JPanel leftPanel = new JPanel(new BorderLayout());
        
        requestListModel = new DefaultListModel<>();
        requestList = new JList<>(requestListModel);
        requestList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        requestList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                selectedRequestIndex = requestList.getSelectedIndex();
                loadSelectedRequest();
            }
        });
        
        JScrollPane listScroll = new JScrollPane(requestList);
        JPanel listControls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addBtn = new JButton("Add");
        JButton removeBtn = new JButton("Remove");
        JButton upBtn = new JButton("↑");
        JButton downBtn = new JButton("↓");
        JButton saveBtn = new JButton("Save");
        
        addBtn.addActionListener(e -> addNewRequest());
        removeBtn.addActionListener(e -> removeSelectedRequest());
        upBtn.addActionListener(e -> moveRequest(-1));
        downBtn.addActionListener(e -> moveRequest(1));
        saveBtn.addActionListener(e -> autoSaveRequest());
        
        listControls.setLayout(new BoxLayout(listControls, BoxLayout.Y_AXIS));
        JPanel addRemovePanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        addRemovePanel.add(addBtn);
        addRemovePanel.add(removeBtn);
        JPanel otherControlsPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        otherControlsPanel.add(upBtn);
        otherControlsPanel.add(downBtn);
        otherControlsPanel.add(saveBtn);
        listControls.add(addRemovePanel);
        listControls.add(otherControlsPanel);
        
        leftPanel.add(listScroll, BorderLayout.CENTER);
        leftPanel.add(listControls, BorderLayout.SOUTH);
        
        JTabbedPane editorTabs = new JTabbedPane();
        
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.add(rawRequestEditor.uiComponent(), BorderLayout.CENTER);
        
        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.add(rawResponseEditor.uiComponent(), BorderLayout.CENTER);
        
        editorTabs.addTab("Request", requestPanel);
        editorTabs.addTab("Response", responsePanel);
        
        JPanel rightPanel = new JPanel(new BorderLayout());
        
        availableVarsArea = new JTextArea(8, 20);
        availableVarsArea.setEditable(false);
        availableVarsArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        availableVarsArea.setBorder(BorderFactory.createTitledBorder("Available Patterns"));
        JScrollPane varsScroll = new JScrollPane(availableVarsArea);
        
        rightPanel.add(varsScroll, BorderLayout.CENTER);
        rightPanel.setPreferredSize(new Dimension(300, 0));
        
        JSplitPane split1 = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        split1.setLeftComponent(leftPanel);
        split1.setRightComponent(editorTabs);
        split1.setResizeWeight(0.2);
        
        JSplitPane split2 = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        split2.setLeftComponent(split1);
        split2.setRightComponent(rightPanel);
        split2.setResizeWeight(0.8);
        
        panel.add(split2);
        return panel;
    }

    private JPanel createTopRightPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        JTabbedPane tabbedPane = new JTabbedPane();
        
        JPanel credPanel = new JPanel(new BorderLayout());
        credPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        credentialsTableModel = new DefaultTableModel(new String[]{"Username", "Password"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return true;
            }
        };
        
        credentialsTable = new JTable(credentialsTableModel);
        credentialsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        JScrollPane credScroll = new JScrollPane(credentialsTable);
        
        JPanel credControls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addCredBtn = new JButton("Add");
        JButton removeCredBtn = new JButton("Remove");
        JButton clearCredBtn = new JButton("Clear");
        JButton loadCredBtn = new JButton("Load...");
        JButton pasteCredBtn = new JButton("Paste");
        
        addCredBtn.addActionListener(e -> {
            credentialsTableModel.addRow(new Object[]{"", ""});
        });
        
        removeCredBtn.addActionListener(e -> {
            int[] selectedRows = credentialsTable.getSelectedRows();
            for (int i = selectedRows.length - 1; i >= 0; i--) {
                credentialsTableModel.removeRow(selectedRows[i]);
            }
        });
        
        clearCredBtn.addActionListener(e -> {
            credentialsTableModel.setRowCount(0);
        });
        
        loadCredBtn.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showOpenDialog(panel) == JFileChooser.APPROVE_OPTION) {
                try {
                    java.io.File file = fileChooser.getSelectedFile();
                    java.util.Scanner scanner = new java.util.Scanner(file);
                    while (scanner.hasNextLine()) {
                        String line = scanner.nextLine().trim();
                        if (!line.isEmpty() && line.contains(":")) {
                            String[] parts = line.split(":", 2);
                            credentialsTableModel.addRow(new Object[]{parts[0].trim(), parts[1].trim()});
                        }
                    }
                    scanner.close();
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(panel, "Error loading file: " + ex.getMessage());
                }
            }
        });
        
        pasteCredBtn.addActionListener(e -> {
            try {
                String clipboard = (String) Toolkit.getDefaultToolkit()
                    .getSystemClipboard().getData(java.awt.datatransfer.DataFlavor.stringFlavor);
                String[] lines = clipboard.split("\n");
                for (String line : lines) {
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
        
        credControls.add(addCredBtn);
        credControls.add(removeCredBtn);
        credControls.add(clearCredBtn);
        credControls.add(loadCredBtn);
        credControls.add(pasteCredBtn);
        
        credPanel.add(credScroll, BorderLayout.CENTER);
        credPanel.add(credControls, BorderLayout.SOUTH);
        
        JPanel varsPanel = new JPanel(new BorderLayout());
        varsPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        staticVarsTableModel = new DefaultTableModel(new String[]{"Variable Name", "Value"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return true;
            }
        };
        
        staticVarsTable = new JTable(staticVarsTableModel);
        staticVarsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        
        staticVarsTableModel.addTableModelListener(e -> updateAvailableVariables());
        
        JScrollPane varsScroll = new JScrollPane(staticVarsTable);
        
        JPanel varsControls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addVarBtn = new JButton("Add");
        JButton removeVarBtn = new JButton("Remove");
        JButton clearVarBtn = new JButton("Clear");
        
        addVarBtn.addActionListener(e -> {
            staticVarsTableModel.addRow(new Object[]{"", ""});
        });
        
        removeVarBtn.addActionListener(e -> {
            int[] selectedRows = staticVarsTable.getSelectedRows();
            for (int i = selectedRows.length - 1; i >= 0; i--) {
                staticVarsTableModel.removeRow(selectedRows[i]);
            }
        });
        
        clearVarBtn.addActionListener(e -> {
            staticVarsTableModel.setRowCount(0);
        });
        
        varsControls.add(addVarBtn);
        varsControls.add(removeVarBtn);
        varsControls.add(clearVarBtn);
        
        varsPanel.add(varsScroll, BorderLayout.CENTER);
        varsPanel.add(varsControls, BorderLayout.SOUTH);
        
        tabbedPane.addTab("Credentials", credPanel);
        tabbedPane.addTab("Static Variables", varsPanel);

        extractionPanel = new JPanel();
        extractionPanel.setLayout(new BoxLayout(extractionPanel, BoxLayout.Y_AXIS));
        JScrollPane extractionScroll = new JScrollPane(extractionPanel);
        extractionScroll.setBorder(BorderFactory.createTitledBorder("Extractions"));
        
        JButton addExtractionBtn = new JButton("Add Extraction");
        JButton addAuthExtractionBtn = new JButton("Extract Auth Value");
        
        addExtractionBtn.addActionListener(e -> addExtraction());
        addAuthExtractionBtn.addActionListener(e -> addAuthExtraction());
        
        JPanel extractionHeader = new JPanel(new FlowLayout(FlowLayout.LEFT));
        extractionHeader.add(addExtractionBtn);
        extractionHeader.add(addAuthExtractionBtn);
        
        JPanel extractionContainer = new JPanel(new BorderLayout());
        extractionContainer.add(extractionHeader, BorderLayout.NORTH);
        extractionContainer.add(extractionScroll, BorderLayout.CENTER);

        JPanel extractionPane = new JPanel(new BorderLayout());
        extractionPane.add(extractionContainer, BorderLayout.CENTER);

        tabbedPane.addTab("Extractions", extractionPane);
        
        panel.add(tabbedPane, BorderLayout.CENTER);
        return panel;
    }
    
    private JPanel createMiddlePanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        JButton executeBtn = new JButton("Execute Pipeline");
        executeBtn.setFont(new Font("Dialog", Font.BOLD, 14));
        executeBtn.addActionListener(e -> executePipeline());
        
        JButton exportBtn = new JButton("Export Pipeline");
        exportBtn.addActionListener(e -> exportPipeline());
        
        JButton importBtn = new JButton("Import Pipeline");
        importBtn.addActionListener(e -> importPipeline());
        
        panel.add(executeBtn);
        panel.add(Box.createHorizontalStrut(20));
        panel.add(exportBtn);
        panel.add(importBtn);
        
        return panel;
    }
    
    private JPanel createBottomLeftPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Execution Logs"));
        
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        JScrollPane scroll = new JScrollPane(logArea);
        
        JButton clearBtn = new JButton("Clear Logs");
        clearBtn.addActionListener(e -> logArea.setText(""));
        
        panel.add(scroll, BorderLayout.CENTER);
        panel.add(clearBtn, BorderLayout.SOUTH);
        return panel;
    }
    
    private JPanel createBottomRightPanel() {
        JPanel mainPanel = new JPanel(new BorderLayout());
        
        JTabbedPane tabbedPane = new JTabbedPane();
        
        JPanel requestInterceptionPanel = new JPanel(new BorderLayout());
        requestInterceptionPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        JPanel reqIntContent = new JPanel();
        reqIntContent.setLayout(new BoxLayout(reqIntContent, BoxLayout.Y_AXIS));
        
        JLabel reqIntTitle = new JLabel("Request Pattern Replacement");
        reqIntTitle.setFont(new Font("Dialog", Font.BOLD, 13));
        reqIntTitle.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        interceptionToggle = new JToggleButton("Enable Request Interception");
        interceptionToggle.setAlignmentX(Component.LEFT_ALIGNMENT);
        interceptionToggle.setMaximumSize(new Dimension(Integer.MAX_VALUE, 35));
        interceptionToggle.addActionListener(e -> {
            interceptionEnabled = interceptionToggle.isSelected();
            if (interceptionEnabled) {
                interceptionToggle.setText("Disable Request Interception");
                interceptionToggle.setBackground(new Color(144, 238, 144));
            } else {
                interceptionToggle.setText("Enable Request Interception");
                interceptionToggle.setBackground(null);
            }
        });
        
        JLabel reqIntInfo = new JLabel("Automatically replaces patterns in outgoing requests");
        reqIntInfo.setFont(new Font("Dialog", Font.PLAIN, 11));
        reqIntInfo.setAlignmentX(Component.LEFT_ALIGNMENT);
        reqIntInfo.setForeground(Color.GRAY);
        
        reqIntContent.add(reqIntTitle);
        reqIntContent.add(Box.createVerticalStrut(10));
        reqIntContent.add(interceptionToggle);
        reqIntContent.add(Box.createVerticalStrut(5));
        reqIntContent.add(Box.createVerticalStrut(10));
        reqIntContent.add(reqIntInfo);
        reqIntContent.add(Box.createVerticalGlue());
        
        requestInterceptionPanel.add(reqIntContent, BorderLayout.NORTH);
        
        JPanel responseInterceptionPanel = new JPanel(new BorderLayout());
        responseInterceptionPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        JPanel respIntContent = new JPanel();
        respIntContent.setLayout(new BoxLayout(respIntContent, BoxLayout.Y_AXIS));
        
        JLabel respIntTitle = new JLabel("Response Session Detection");
        respIntTitle.setFont(new Font("Dialog", Font.BOLD, 13));
        respIntTitle.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        interceptionResToggle = new JToggleButton("Enable Response Interception");
        interceptionResToggle.setAlignmentX(Component.LEFT_ALIGNMENT);
        interceptionResToggle.setMaximumSize(new Dimension(Integer.MAX_VALUE, 35));
        interceptionResToggle.addActionListener(e -> {
            interceptionResEnabled = interceptionResToggle.isSelected();
            if (interceptionResEnabled) {
                interceptionResToggle.setText("Disable Response Interception");
                interceptionResToggle.setBackground(new Color(144, 238, 144));
            } else {
                interceptionResToggle.setText("Enable Response Interception");
                interceptionResToggle.setBackground(null);
            }
        });
        
        JLabel respIntInfo = new JLabel("Auto-refresh sessions when expiration strings detected");
        respIntInfo.setFont(new Font("Dialog", Font.PLAIN, 11));
        respIntInfo.setAlignmentX(Component.LEFT_ALIGNMENT);
        respIntInfo.setForeground(Color.GRAY);
        
        JPanel expirationPanel = new JPanel(new BorderLayout());
        expirationPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(Color.LIGHT_GRAY), 
            "Session Expiration Strings (one per line)"
        ));
        expirationPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        expirationPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 200));
        
        expirationStringsArea = new JTextArea(5, 20);
        expirationStringsArea.setLineWrap(true);
        expirationStringsArea.setWrapStyleWord(false);
        expirationStringsArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        JScrollPane expirationScroll = new JScrollPane(expirationStringsArea);
        
        JPanel expirationControls = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        JButton addExpBtn = new JButton("Add");
        JButton pasteExpBtn = new JButton("Paste");
        JButton clearExpBtn = new JButton("Clear");
        
        addExpBtn.addActionListener(e -> {
            String value = JOptionPane.showInputDialog(mainPanel, "Enter expiration string:");
            if (value != null && !value.trim().isEmpty()) {
                String current = expirationStringsArea.getText();
                if (!current.isEmpty() && !current.endsWith("\n")) {
                    current += "\n";
                }
                expirationStringsArea.setText(current + value.trim());
                updateExpirationStringsList();
            }
        });
        
        pasteExpBtn.addActionListener(e -> {
            try {
                String clipboard = (String) Toolkit.getDefaultToolkit()
                    .getSystemClipboard().getData(java.awt.datatransfer.DataFlavor.stringFlavor);
                String current = expirationStringsArea.getText();
                if (!current.isEmpty() && !current.endsWith("\n")) {
                    current += "\n";
                }
                expirationStringsArea.setText(current + clipboard);
                updateExpirationStringsList();
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(mainPanel, "Error pasting: " + ex.getMessage());
            }
        });
        
        clearExpBtn.addActionListener(e -> {
            expirationStringsArea.setText("");
            updateExpirationStringsList();
        });
        
        expirationControls.add(addExpBtn);
        expirationControls.add(pasteExpBtn);
        expirationControls.add(clearExpBtn);
        
        expirationPanel.add(expirationScroll, BorderLayout.CENTER);
        expirationPanel.add(expirationControls, BorderLayout.SOUTH);
        
        respIntContent.add(respIntTitle);
        respIntContent.add(Box.createVerticalStrut(10));
        respIntContent.add(interceptionResToggle);
        respIntContent.add(Box.createVerticalStrut(5));
        respIntContent.add(Box.createVerticalStrut(10));
        respIntContent.add(respIntInfo);
        respIntContent.add(Box.createVerticalStrut(15));
        respIntContent.add(expirationPanel);
        respIntContent.add(Box.createVerticalGlue());
        
        responseInterceptionPanel.add(respIntContent, BorderLayout.NORTH);
        
        JPanel httpConfigPanel = new JPanel(new BorderLayout());
        httpConfigPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        JPanel httpConfigContent = new JPanel();
        httpConfigContent.setLayout(new BoxLayout(httpConfigContent, BoxLayout.Y_AXIS));
        
        JLabel httpConfigTitle = new JLabel("HTTP Service Configuration");
        httpConfigTitle.setFont(new Font("Dialog", Font.BOLD, 13));
        httpConfigTitle.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        JLabel httpConfigInfo = new JLabel("Default settings for pipeline requests");
        httpConfigInfo.setFont(new Font("Dialog", Font.PLAIN, 11));
        httpConfigInfo.setAlignmentX(Component.LEFT_ALIGNMENT);
        httpConfigInfo.setForeground(Color.GRAY);
        
        JPanel portPanel = new JPanel();
        portPanel.setLayout(new BoxLayout(portPanel, BoxLayout.X_AXIS));
        portPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        portPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 35));
        portPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color.LIGHT_GRAY),
            BorderFactory.createEmptyBorder(5, 10, 5, 10)
        ));
        
        JLabel portLabel = new JLabel("Default Port:");
        portLabel.setFont(new Font("Dialog", Font.PLAIN, 12));
        defaultPortField = new JTextField("443", 8);
        defaultPortField.setFont(new Font("Monospaced", Font.PLAIN, 12));
        defaultPortField.setMaximumSize(new Dimension(100, 25));
        defaultPortField.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) { updatePort(); }
            public void removeUpdate(DocumentEvent e) { updatePort(); }
            public void insertUpdate(DocumentEvent e) { updatePort(); }
        });
        
        portPanel.add(portLabel);
        portPanel.add(Box.createHorizontalStrut(10));
        portPanel.add(defaultPortField);
        portPanel.add(Box.createHorizontalGlue());
        
        JPanel httpsPanel = new JPanel();
        httpsPanel.setLayout(new BoxLayout(httpsPanel, BoxLayout.X_AXIS));
        httpsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        httpsPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 35));
        httpsPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color.LIGHT_GRAY),
            BorderFactory.createEmptyBorder(5, 10, 5, 10)
        ));
        
        forceHttpsCheckbox = new JCheckBox("Force HTTPS Protocol", true);
        forceHttpsCheckbox.setFont(new Font("Dialog", Font.PLAIN, 12));
        forceHttpsCheckbox.addActionListener(e -> {
            configuredHttps = forceHttpsCheckbox.isSelected();
            if (configuredHttps && configuredPort == 80) {
                defaultPortField.setText("443");
            } else if (!configuredHttps && configuredPort == 443) {
                defaultPortField.setText("80");
            }
        });
        
        httpsPanel.add(forceHttpsCheckbox);
        httpsPanel.add(Box.createHorizontalGlue());
        
        JLabel warningLabel = new JLabel("⚠ These settings apply to all pipeline requests");
        warningLabel.setFont(new Font("Dialog", Font.PLAIN, 10));
        warningLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        warningLabel.setForeground(new Color(200, 100, 0));
        
        httpConfigContent.add(httpConfigTitle);
        httpConfigContent.add(Box.createVerticalStrut(10));
        httpConfigContent.add(httpConfigInfo);
        httpConfigContent.add(Box.createVerticalStrut(15));
        httpConfigContent.add(portPanel);
        httpConfigContent.add(Box.createVerticalStrut(10));
        httpConfigContent.add(httpsPanel);
        httpConfigContent.add(Box.createVerticalStrut(10));
        httpConfigContent.add(warningLabel);
        httpConfigContent.add(Box.createVerticalGlue());
        
        httpConfigPanel.add(httpConfigContent, BorderLayout.NORTH);
        
        tabbedPane.addTab("Request Interception", requestInterceptionPanel);
        tabbedPane.addTab("Response Detection", responseInterceptionPanel);
        tabbedPane.addTab("HTTP Config", httpConfigPanel);
        
        mainPanel.add(tabbedPane, BorderLayout.CENTER);
        
        return mainPanel;
    }

    private JPanel createConfigPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("HTTP Configuration"));
        
        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        JPanel portPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        portPanel.add(new JLabel("Default Port:"));
        defaultPortField = new JTextField("443", 8);
        defaultPortField.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) { updatePort(); }
            public void removeUpdate(DocumentEvent e) { updatePort(); }
            public void insertUpdate(DocumentEvent e) { updatePort(); }
        });
        portPanel.add(defaultPortField);
        
        forceHttpsCheckbox = new JCheckBox("Force HTTPS", true);
        forceHttpsCheckbox.addActionListener(e -> {
            configuredHttps = forceHttpsCheckbox.isSelected();
            if (configuredHttps && configuredPort == 80) {
                defaultPortField.setText("443");
            } else if (!configuredHttps && configuredPort == 443) {
                defaultPortField.setText("80");
            }
        });
        
        contentPanel.add(portPanel);
        contentPanel.add(forceHttpsCheckbox);
        contentPanel.add(Box.createVerticalGlue());
        
        panel.add(contentPanel, BorderLayout.NORTH);
        return panel;
    }

    private void updatePort() {
        try {
            int newPort = Integer.parseInt(defaultPortField.getText().trim());
            if (newPort > 0 && newPort <= 65535) {
                configuredPort = newPort;
            }
        } catch (NumberFormatException e) {
            // Invalid port, keep previous value
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
        
        JButton removeBtn = new JButton("Remove");
        
        typeCombo.addActionListener(e -> {
            ext.type = typeCombo.getSelectedIndex();
            updateExampleText(exampleArea, ext.type);
        });
        
        valueField.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) { ext.value = valueField.getText(); }
            public void removeUpdate(DocumentEvent e) { ext.value = valueField.getText(); }
            public void insertUpdate(DocumentEvent e) { ext.value = valueField.getText(); }
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
        
        JPanel typePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        typePanel.add(new JLabel("Type: "));
        typePanel.add(typeCombo);
        
        JPanel valuePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        valuePanel.add(new JLabel("Value: "));
        valuePanel.add(valueField);
        
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        btnPanel.add(removeBtn);
        
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
        
        typeCombo.addActionListener(e -> {
            authExt.type = typeCombo.getSelectedIndex();
            updateExampleText(exampleArea, authExt.type);
        });
        
        valueField.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) { authExt.value = valueField.getText(); }
            public void removeUpdate(DocumentEvent e) { authExt.value = valueField.getText(); }
            public void insertUpdate(DocumentEvent e) { authExt.value = valueField.getText(); }
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
        
        JPanel typePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        typePanel.add(new JLabel("Type: "));
        typePanel.add(typeCombo);
        
        JPanel valuePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        valuePanel.add(new JLabel("Value: "));
        valuePanel.add(valueField);
        
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        btnPanel.add(removeBtn);
        
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

    private void executePipeline() {
        autoSaveRequest();
        
        new Thread(() -> {
            try {
                executePipelineInBackground();
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    log("✖ Fatal error: " + e.getMessage());
                    showError("Fatal error during pipeline execution:\n\n" + e.getMessage() + 
                             "\n\nStack trace:\n" + getStackTrace(e));
                });
            }
        }).start();
    }
    
    private void executePipelineInBackground() {
        SwingUtilities.invokeLater(() -> {
            logArea.setText("");
            log("=== Starting Pipeline Execution ===\n");
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
            });
            return;
        }
        
        for (int i = 0; i < credList.size(); i++) {
            String[] cred = credList.get(i);
            log("\n--- Credential Set " + (i + 1) + ": " + cred[0] + " ---");
            
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
                executePipelineForCredential(variables, cred[0]);
                log("✓ Pipeline completed successfully for " + cred[0]);
            } catch (Exception e) {
                log("✗ Pipeline failed for " + cred[0] + ": " + e.getMessage());
                final String errorMsg = "Pipeline failed for " + cred[0] + ":\n\n" + e.getMessage() + 
                         "\n\nStack trace:\n" + getStackTrace(e);
                SwingUtilities.invokeLater(() -> showError(errorMsg));
            }
        }
        
        log("\n=== Pipeline Execution Complete ===");
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
        json.append("  }\n");
        
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
