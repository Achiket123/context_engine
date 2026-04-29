// package main

// import (
// 	"bytes"
// 	"crypto/md5"
// 	"encoding/json"
// 	"fmt"
// 	"io/fs"
// 	"os"
// 	"os/exec"
// 	"path/filepath"
// 	"regexp"
// 	"runtime"
// 	"sort"
// 	"strconv"
// 	"strings"
// 	"time"
// )

// // Config holds engine configuration
// type Config struct {
// 	MaxFileSize       int64    `json:"max_file_size"`
// 	MaxTotalTokens    int      `json:"max_total_tokens"`
// 	ExcludePatterns   []string `json:"exclude_patterns"`
// 	IncludeExtensions []string `json:"include_extensions"`
// 	EnableSecurity    bool     `json:"enable_security"`
// 	UseGosec          bool     `json:"use_gosec"`
// 	UseBandit         bool     `json:"use_bandit"`
// 	UseESLint         bool     `json:"use_eslint"`
// 	UseFlawfinder     bool     `json:"use_flawfinder"`
// 	UsePhpStan        bool     `json:"use_phpstan"`
// 	UseRubocop        bool     `json:"use_rubocop"`
// 	CacheEnabled      bool     `json:"cache_enabled"`
// 	CacheDir          string   `json:"cache_dir"`
// }

// // FileContext represents a processed file
// type FileContext struct {
// 	Path         string          `json:"path"`
// 	Content      string          `json:"content"`
// 	Hash         string          `json:"hash"`
// 	Size         int64           `json:"size"`
// 	Tokens       int             `json:"tokens"`
// 	ModifiedTime time.Time       `json:"modified_time"`
// 	Language     string          `json:"language"`
// 	Imports      []string        `json:"imports"`
// 	Functions    []string        `json:"functions"`
// 	Security     []SecurityIssue `json:"security,omitempty"`
// }

// // SecurityIssue represents a potential security threat
// type SecurityIssue struct {
// 	Severity    string `json:"severity"`
// 	Type        string `json:"type"`
// 	Description string `json:"description"`
// 	Line        int    `json:"line"`
// 	Column      int    `json:"column"`
// 	File        string `json:"file"`
// 	Code        string `json:"code"`
// 	Tool        string `json:"tool"`
// 	CWE         string `json:"cwe,omitempty"`
// 	Confidence  string `json:"confidence,omitempty"`
// }

// // GosecIssue represents gosec JSON output
// type GosecIssue struct {
// 	Severity   string `json:"severity"`
// 	Confidence string `json:"confidence"`
// 	RuleID     string `json:"rule_id"`
// 	Details    string `json:"details"`
// 	File       string `json:"file"`
// 	Code       string `json:"code"`
// 	Line       string `json:"line"`
// 	Column     string `json:"column"`
// 	CWE        struct {
// 		ID string `json:"id"`
// 	} `json:"cwe"`
// }

// type GosecOutput struct {
// 	Issues []GosecIssue `json:"Issues"`
// }

// // BanditResult represents bandit JSON output
// type BanditResult struct {
// 	Results []struct {
// 		TestID          string `json:"test_id"`
// 		IssueConfidence string `json:"issue_confidence"`
// 		IssueSeverity   string `json:"issue_severity"`
// 		IssueText       string `json:"issue_text"`
// 		LineNumber      int    `json:"line_number"`
// 		Code            string `json:"code"`
// 		Filename        string `json:"filename"`
// 		CWE             struct {
// 			ID int `json:"id"`
// 		} `json:"cwe"`
// 	} `json:"results"`
// }

// // ESLintResult represents eslint JSON output
// type ESLintResult []struct {
// 	FilePath string `json:"filePath"`
// 	Messages []struct {
// 		RuleID   string `json:"ruleId"`
// 		Severity int    `json:"severity"`
// 		Message  string `json:"message"`
// 		Line     int    `json:"line"`
// 		Column   int    `json:"column"`
// 	} `json:"messages"`
// }

// // SecurityPattern defines regex-based security patterns
// type SecurityPattern struct {
// 	Pattern     *regexp.Regexp
// 	Type        string
// 	Severity    string
// 	Description string
// 	Languages   []string
// }

// // ContextEngine manages code context generation
// type ContextEngine struct {
// 	Config      Config
// 	Files       []FileContext
// 	Cache       map[string]FileContext
// 	SecurityDB  []SecurityPattern
// 	ProjectPath string
// }

// // NewContextEngine initializes the engine
// func NewContextEngine(cfg Config) *ContextEngine {
// 	engine := &ContextEngine{
// 		Config:     cfg,
// 		Files:      make([]FileContext, 0),
// 		Cache:      make(map[string]FileContext),
// 		SecurityDB: initSecurityPatterns(),
// 	}

// 	if cfg.CacheEnabled {
// 		engine.loadCache()
// 	}

// 	return engine
// }

// // initSecurityPatterns defines comprehensive multi-language patterns
// func initSecurityPatterns() []SecurityPattern {
// 	patterns := []SecurityPattern{
// 		{
// 			Pattern:     regexp.MustCompile(`(?i)(password|passwd|pwd|secret|api_key|apikey|token|private_key)\s*=\s*["'][^"']{8,}["']`),
// 			Type:        "Hardcoded Credentials",
// 			Severity:    "CRITICAL",
// 			Description: "Hardcoded credentials detected",
// 			Languages:   []string{"*"},
// 		},
// 		{
// 			Pattern:     regexp.MustCompile(`(?i)(aws_access_key|aws_secret|AKIA[0-9A-Z]{16})`),
// 			Type:        "AWS Credentials",
// 			Severity:    "CRITICAL",
// 			Description: "AWS credentials exposed",
// 			Languages:   []string{"*"},
// 		},
// 		{
// 			Pattern:     regexp.MustCompile(`(execute|query|exec)\s*\([^)]*\+|fmt\.Sprintf.*SELECT|SELECT.*%s|"SELECT.*"\s*\+`),
// 			Type:        "SQL Injection",
// 			Severity:    "CRITICAL",
// 			Description: "Potential SQL injection vulnerability",
// 			Languages:   []string{"go", "python", "javascript", "typescript", "php", "java", "kotlin", "scala", "swift"},
// 		},
// 		{
// 			Pattern:     regexp.MustCompile(`(exec\.Command|os\.system|subprocess\.call|eval|shell_exec|system)\s*\([^)]*\+`),
// 			Type:        "Command Injection",
// 			Severity:    "HIGH",
// 			Description: "Dynamic command construction - potential command injection",
// 			Languages:   []string{"go", "python", "javascript", "php", "ruby", "perl", "lua"},
// 		},
// 		{
// 			Pattern:     regexp.MustCompile(`innerHTML\s*=|document\.write\(|\.html\([^)]*\+`),
// 			Type:        "XSS Vulnerability",
// 			Severity:    "HIGH",
// 			Description: "Potential XSS - dynamic HTML content",
// 			Languages:   []string{"javascript", "typescript"},
// 		},
// 		{
// 			Pattern:     regexp.MustCompile(`(os\.Open|ioutil\.ReadFile|open\(|file_get_contents|readFile)\s*\([^)]*\+`),
// 			Type:        "Path Traversal",
// 			Severity:    "HIGH",
// 			Description: "Dynamic file path - potential path traversal",
// 			Languages:   []string{"go", "python", "javascript", "php", "ruby", "swift", "kotlin"},
// 		},
// 		{
// 			Pattern:     regexp.MustCompile(`(MD5|SHA1|DES|RC4|md5|sha1)\s*\(`),
// 			Type:        "Weak Cryptography",
// 			Severity:    "MEDIUM",
// 			Description: "Use of weak cryptographic algorithm",
// 			Languages:   []string{"*"},
// 		},
// 		{
// 			Pattern:     regexp.MustCompile(`Math\.random|rand\(\)|mt_rand\(\)`),
// 			Type:        "Weak Random",
// 			Severity:    "MEDIUM",
// 			Description: "Weak random number generator for security",
// 			Languages:   []string{"javascript", "php", "c", "cpp", "lua"},
// 		},
// 		{
// 			Pattern:     regexp.MustCompile(`(pickle\.loads|yaml\.load|unserialize|eval\(|json\.loads.*JSONDecoder)`),
// 			Type:        "Unsafe Deserialization",
// 			Severity:    "HIGH",
// 			Description: "Unsafe deserialization of untrusted data",
// 			Languages:   []string{"python", "php", "javascript", "ruby", "perl"},
// 		},
// 		{
// 			Pattern:     regexp.MustCompile(`(http\.Get|requests\.get|fetch|curl_exec|Net::HTTP)\s*\([^)]*\+`),
// 			Type:        "SSRF",
// 			Severity:    "HIGH",
// 			Description: "Server-Side Request Forgery risk",
// 			Languages:   []string{"go", "python", "javascript", "php", "ruby", "swift", "kotlin"},
// 		},
// 		{
// 			Pattern:     regexp.MustCompile(`\beval\s*\(|exec\s*\(|Function\s*\(`),
// 			Type:        "Code Injection",
// 			Severity:    "CRITICAL",
// 			Description: "Dynamic code execution",
// 			Languages:   []string{"javascript", "python", "php", "perl", "lua", "ruby"},
// 		},
// 		{
// 			Pattern:     regexp.MustCompile(`\b(gets|strcpy|strcat|sprintf|vsprintf)\s*\(`),
// 			Type:        "Buffer Overflow",
// 			Severity:    "CRITICAL",
// 			Description: "Unsafe buffer function",
// 			Languages:   []string{"c", "cpp"},
// 		},
// 		{
// 			Pattern:     regexp.MustCompile(`XMLParser|parseXML|DocumentBuilder.*parse|simplexml_load`),
// 			Type:        "XXE Risk",
// 			Severity:    "HIGH",
// 			Description: "XML parser may be vulnerable to XXE",
// 			Languages:   []string{"java", "php", "python", "javascript", "kotlin", "scala"},
// 		},
// 		{
// 			Pattern:     regexp.MustCompile(`(?i)(console\.log|print\(|var_dump|debug|TODO.*security|FIXME.*security)`),
// 			Type:        "Debug Code",
// 			Severity:    "LOW",
// 			Description: "Debug code or security TODO in production",
// 			Languages:   []string{"*"},
// 		},
// 	}

// 	return patterns
// }

// // CheckToolsAvailable verifies required tools are installed
// func (e *ContextEngine) CheckToolsAvailable() {
// 	tools := map[string]*bool{
// 		"gosec":      &e.Config.UseGosec,
// 		"bandit":     &e.Config.UseBandit,
// 		"eslint":     &e.Config.UseESLint,
// 		"flawfinder": &e.Config.UseFlawfinder,
// 		"phpstan":    &e.Config.UsePhpStan,
// 		"rubocop":    &e.Config.UseRubocop,
// 	}

// 	fmt.Println("Checking available security tools:")
// 	for tool, enabled := range tools {
// 		if *enabled {
// 			if _, err := exec.LookPath(tool); err != nil {
// 				fmt.Printf("  %s not found (disabled)\n", tool)
// 				*enabled = false
// 			} else {
// 				fmt.Printf("  %s found\n", tool)
// 			}
// 		}
// 	}
// 	fmt.Println()
// }

// // RunGosec executes gosec on Go files
// func (e *ContextEngine) RunGosec() ([]SecurityIssue, error) {
// 	if !e.Config.UseGosec {
// 		return nil, nil
// 	}

// 	fmt.Println("Running gosec analysis...")
// 	cmd := exec.Command("gosec", "-fmt=json", "-quiet", "./...")
// 	cmd.Dir = e.ProjectPath

// 	output, _ := cmd.CombinedOutput()
// 	if len(output) == 0 {
// 		return nil, nil
// 	}

// 	var result GosecOutput
// 	if err := json.Unmarshal(output, &result); err != nil {
// 		return nil, fmt.Errorf("failed to parse gosec output: %v", err)
// 	}

// 	issues := make([]SecurityIssue, 0)
// 	for _, issue := range result.Issues {
// 		var line int
// 		fmt.Sscanf(issue.Line, "%d", &line)

// 		relPath, _ := filepath.Rel(e.ProjectPath, issue.File)

// 		issues = append(issues, SecurityIssue{
// 			Severity:    strings.ToUpper(issue.Severity),
// 			Type:        issue.RuleID,
// 			Description: issue.Details,
// 			Line:        line,
// 			File:        relPath,
// 			Code:        issue.Code,
// 			Tool:        "gosec",
// 			CWE:         issue.CWE.ID,
// 			Confidence:  issue.Confidence,
// 		})
// 	}

// 	fmt.Printf("  Found %d issues with gosec\n", len(issues))
// 	return issues, nil
// }

// // RunBandit executes bandit on Python files
// func (e *ContextEngine) RunBandit() ([]SecurityIssue, error) {
// 	if !e.Config.UseBandit {
// 		return nil, nil
// 	}

// 	fmt.Println("Running bandit analysis...")
// 	cmd := exec.Command("bandit", "-r", ".", "-f", "json", "-q")
// 	cmd.Dir = e.ProjectPath

// 	output, _ := cmd.CombinedOutput()
// 	if len(output) == 0 {
// 		return nil, nil
// 	}

// 	var result BanditResult
// 	if err := json.Unmarshal(output, &result); err != nil {
// 		return nil, fmt.Errorf("failed to parse bandit output: %v", err)
// 	}

// 	issues := make([]SecurityIssue, 0)
// 	for _, finding := range result.Results {
// 		relPath, _ := filepath.Rel(e.ProjectPath, finding.Filename)

// 		severity := strings.ToUpper(finding.IssueSeverity)
// 		if severity == "UNDEFINED" {
// 			severity = "MEDIUM"
// 		}

// 		cwe := ""
// 		if finding.CWE.ID > 0 {
// 			cwe = fmt.Sprintf("CWE-%d", finding.CWE.ID)
// 		}

// 		issues = append(issues, SecurityIssue{
// 			Severity:    severity,
// 			Type:        finding.TestID,
// 			Description: finding.IssueText,
// 			Line:        finding.LineNumber,
// 			File:        relPath,
// 			Code:        finding.Code,
// 			Tool:        "bandit",
// 			CWE:         cwe,
// 			Confidence:  finding.IssueConfidence,
// 		})
// 	}

// 	fmt.Printf("  Found %d issues with bandit\n", len(issues))
// 	return issues, nil
// }

// // RunESLint executes eslint with security plugin
// func (e *ContextEngine) RunESLint() ([]SecurityIssue, error) {
// 	if !e.Config.UseESLint {
// 		return nil, nil
// 	}

// 	fmt.Println("Running eslint analysis...")
// 	cmd := exec.Command("eslint", ".", "--ext", ".js,.jsx,.ts,.tsx", "-f", "json")
// 	cmd.Dir = e.ProjectPath

// 	output, _ := cmd.CombinedOutput()
// 	if len(output) == 0 {
// 		return nil, nil
// 	}

// 	idx := bytes.IndexByte(output, '[')
// 	if idx == -1 {
// 		return nil, fmt.Errorf("failed to parse eslint output: no JSON array found")
// 	}
// 	output = output[idx:]

// 	var result ESLintResult
// 	if err := json.Unmarshal(output, &result); err != nil {
// 		return nil, fmt.Errorf("failed to parse eslint output: %v", err)
// 	}

// 	issues := make([]SecurityIssue, 0)
// 	for _, file := range result {
// 		relPath, _ := filepath.Rel(e.ProjectPath, file.FilePath)

// 		for _, msg := range file.Messages {
// 			if msg.RuleID == "" || msg.Severity < 1 {
// 				continue
// 			}

// 			if !strings.Contains(msg.RuleID, "security") &&
// 				!strings.Contains(msg.RuleID, "no-eval") &&
// 				!strings.Contains(msg.RuleID, "no-implied-eval") {
// 				continue
// 			}

// 			severity := "MEDIUM"
// 			if msg.Severity == 2 {
// 				severity = "HIGH"
// 			}

// 			issues = append(issues, SecurityIssue{
// 				Severity:    severity,
// 				Type:        msg.RuleID,
// 				Description: msg.Message,
// 				Line:        msg.Line,
// 				Column:      msg.Column,
// 				File:        relPath,
// 				Tool:        "eslint",
// 			})
// 		}
// 	}

// 	fmt.Printf("  Found %d issues with eslint\n", len(issues))
// 	return issues, nil
// }

// // RunFlawfinder executes flawfinder on C/C++ files
// func (e *ContextEngine) RunFlawfinder() ([]SecurityIssue, error) {
// 	if !e.Config.UseFlawfinder {
// 		return nil, nil
// 	}

// 	fmt.Println("Running flawfinder analysis...")
// 	cmd := exec.Command("flawfinder", "--quiet", "--dataonly", ".")
// 	cmd.Dir = e.ProjectPath

// 	output, _ := cmd.CombinedOutput()
// 	if len(output) == 0 {
// 		return nil, nil
// 	}

// 	issues := make([]SecurityIssue, 0)
// 	lines := strings.Split(string(output), "\n")

// 	for _, line := range lines {
// 		if line == "" {
// 			continue
// 		}

// 		re := regexp.MustCompile(`([^:]+):(\d+):(\d+):\s*\[(\d+)\]\s*\(([^)]+)\)\s*(.+)`)
// 		matches := re.FindStringSubmatch(line)

// 		if len(matches) == 7 {
// 			var lineNum, level int
// 			fmt.Sscanf(matches[2], "%d", &lineNum)
// 			fmt.Sscanf(matches[4], "%d", &level)

// 			severity := "LOW"
// 			if level >= 4 {
// 				severity = "HIGH"
// 			} else if level >= 2 {
// 				severity = "MEDIUM"
// 			}

// 			relPath, _ := filepath.Rel(e.ProjectPath, matches[1])

// 			issues = append(issues, SecurityIssue{
// 				Severity:    severity,
// 				Type:        matches[5],
// 				Description: matches[6],
// 				Line:        lineNum,
// 				File:        relPath,
// 				Tool:        "flawfinder",
// 			})
// 		}
// 	}

// 	fmt.Printf("  Found %d issues with flawfinder\n", len(issues))
// 	return issues, nil
// }

// // isRootDirectory checks if a path is the OS root directory
// func isRootDirectory(path string) bool {
// 	absPath, err := filepath.Abs(path)
// 	if err != nil {
// 		return false
// 	}
// 	absPath = filepath.Clean(absPath)

// 	if runtime.GOOS == "windows" {
// 		// On Windows, root looks like C:\ or D:\
// 		// filepath.VolumeName returns "C:" etc.
// 		vol := filepath.VolumeName(absPath)
// 		if vol == "" {
// 			return false
// 		}
// 		withSep := vol + string(filepath.Separator)
// 		return absPath == withSep || absPath == vol
// 	}

// 	return absPath == "/"
// }

// // ScanDirectory walks the directory and processes files
// func (e *ContextEngine) ScanDirectory(root string) error {
// 	e.ProjectPath = root

// 	var allSecurityIssues []SecurityIssue

// 	if e.Config.EnableSecurity {
// 		tools := []func() ([]SecurityIssue, error){
// 			e.RunGosec,
// 			e.RunBandit,
// 			e.RunESLint,
// 			e.RunFlawfinder,
// 		}

// 		for _, tool := range tools {
// 			if issues, err := tool(); err != nil {
// 				fmt.Printf("Warning: %v\n", err)
// 			} else {
// 				allSecurityIssues = append(allSecurityIssues, issues...)
// 			}
// 		}
// 	}

// 	securityByFile := make(map[string][]SecurityIssue)
// 	for _, issue := range allSecurityIssues {
// 		securityByFile[issue.File] = append(securityByFile[issue.File], issue)
// 	}

// 	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
// 		if err != nil {
// 			return err
// 		}

// 		if d.IsDir() {
// 			if e.shouldExclude(path) {
// 				return filepath.SkipDir
// 			}
// 			return nil
// 		}

// 		if !e.shouldInclude(path) {
// 			return nil
// 		}

// 		info, err := d.Info()
// 		if err != nil {
// 			return nil
// 		}

// 		if info.Size() > e.Config.MaxFileSize {
// 			return nil
// 		}

// 		relPath, _ := filepath.Rel(root, path)
// 		return e.processFile(path, relPath, info, securityByFile[relPath])
// 	})
// }

// func (e *ContextEngine) shouldExclude(path string) bool {
// 	base := filepath.Base(path)
// 	for _, pattern := range e.Config.ExcludePatterns {
// 		if base == pattern {
// 			return true
// 		}
// 	}
// 	return false
// }

// func (e *ContextEngine) shouldInclude(path string) bool {
// 	ext := filepath.Ext(path)
// 	for _, validExt := range e.Config.IncludeExtensions {
// 		if ext == validExt {
// 			return true
// 		}
// 	}
// 	return false
// }

// func (e *ContextEngine) processFile(path, relPath string, info fs.FileInfo, fileIssues []SecurityIssue) error {
// 	hash := e.getFileHash(path)

// 	if e.Config.CacheEnabled {
// 		if cached, exists := e.Cache[hash]; exists {
// 			if cached.ModifiedTime.Equal(info.ModTime()) {
// 				e.Files = append(e.Files, cached)
// 				return nil
// 			}
// 		}
// 	}

// 	content, err := os.ReadFile(path)
// 	if err != nil {
// 		return nil
// 	}

// 	ctx := FileContext{
// 		Path:         relPath,
// 		Content:      string(content),
// 		Hash:         hash,
// 		Size:         info.Size(),
// 		Tokens:       estimateTokens(string(content)),
// 		ModifiedTime: info.ModTime(),
// 		Language:     detectLanguage(path),
// 		Security:     make([]SecurityIssue, 0),
// 	}

// 	ctx.Imports = extractImports(ctx.Content, ctx.Language)
// 	ctx.Functions = extractFunctions(ctx.Content, ctx.Language)

// 	if fileIssues != nil {
// 		ctx.Security = append(ctx.Security, fileIssues...)
// 	}

// 	if e.Config.EnableSecurity {
// 		regexIssues := e.analyzeSecurityThreatsRegex(ctx.Content, ctx.Language)
// 		ctx.Security = append(ctx.Security, regexIssues...)
// 	}

// 	e.Files = append(e.Files, ctx)

// 	if e.Config.CacheEnabled {
// 		e.Cache[hash] = ctx
// 	}

// 	return nil
// }

// func (e *ContextEngine) analyzeSecurityThreatsRegex(content, lang string) []SecurityIssue {
// 	issues := make([]SecurityIssue, 0)
// 	lines := strings.Split(content, "\n")

// 	for i, line := range lines {
// 		for _, pattern := range e.SecurityDB {
// 			if !e.patternApplies(pattern, lang) {
// 				continue
// 			}

// 			if pattern.Pattern.MatchString(line) {
// 				issues = append(issues, SecurityIssue{
// 					Severity:    pattern.Severity,
// 					Type:        pattern.Type,
// 					Description: pattern.Description,
// 					Line:        i + 1,
// 					Code:        strings.TrimSpace(line),
// 					Tool:        "regex",
// 				})
// 			}
// 		}
// 	}

// 	return issues
// }

// func (e *ContextEngine) patternApplies(pattern SecurityPattern, lang string) bool {
// 	for _, l := range pattern.Languages {
// 		if l == "*" || l == lang {
// 			return true
// 		}
// 	}
// 	return false
// }

// func (e *ContextEngine) GenerateContext() string {
// 	var sb strings.Builder
// 	totalTokens := 0

// 	sort.Slice(e.Files, func(i, j int) bool {
// 		if len(e.Files[i].Security) != len(e.Files[j].Security) {
// 			return len(e.Files[i].Security) > len(e.Files[j].Security)
// 		}
// 		return e.Files[i].Tokens > e.Files[j].Tokens
// 	})

// 	sb.WriteString("# Code Context Analysis\n\n")
// 	sb.WriteString(fmt.Sprintf("Generated: %s\n", time.Now().Format(time.RFC3339)))
// 	sb.WriteString(fmt.Sprintf("Files Scanned: %d\n", len(e.Files)))

// 	tools := []string{"regex"}
// 	if e.Config.UseGosec {
// 		tools = append(tools, "gosec")
// 	}
// 	if e.Config.UseBandit {
// 		tools = append(tools, "bandit")
// 	}
// 	if e.Config.UseESLint {
// 		tools = append(tools, "eslint")
// 	}
// 	if e.Config.UseFlawfinder {
// 		tools = append(tools, "flawfinder")
// 	}
// 	sb.WriteString(fmt.Sprintf("Analysis Tools: %s\n\n", strings.Join(tools, ", ")))

// 	if e.Config.EnableSecurity {
// 		sb.WriteString("## Security Summary\n\n")
// 		critical, high, medium, low := e.countSecurityIssues()
// 		total := critical + high + medium + low

// 		sb.WriteString(fmt.Sprintf("Total Issues: %d\n\n", total))
// 		sb.WriteString(fmt.Sprintf("- CRITICAL: %d\n", critical))
// 		sb.WriteString(fmt.Sprintf("- HIGH: %d\n", high))
// 		sb.WriteString(fmt.Sprintf("- MEDIUM: %d\n", medium))
// 		sb.WriteString(fmt.Sprintf("- LOW: %d\n\n", low))

// 		toolCounts := e.countIssuesByTool()
// 		sb.WriteString("Issues by Tool:\n")
// 		for tool, count := range toolCounts {
// 			if count > 0 {
// 				sb.WriteString(fmt.Sprintf("- %s: %d\n", tool, count))
// 			}
// 		}
// 		sb.WriteString("\n")
// 	}

// 	includedCount := 0
// 	for _, file := range e.Files {
// 		if totalTokens+file.Tokens > e.Config.MaxTotalTokens {
// 			break
// 		}

// 		sb.WriteString(fmt.Sprintf("## File: %s\n", file.Path))
// 		sb.WriteString(fmt.Sprintf("Language: %s | Tokens: %d | Size: %d bytes\n\n", file.Language, file.Tokens, file.Size))

// 		if len(file.Imports) > 0 {
// 			sb.WriteString("Imports: " + strings.Join(file.Imports, ", ") + "\n\n")
// 		}

// 		if len(file.Security) > 0 {
// 			sb.WriteString("Security Issues:\n\n")
// 			for _, issue := range file.Security {
// 				sb.WriteString(fmt.Sprintf("[%s] Line %d - %s\n", issue.Severity, issue.Line, issue.Type))
// 				sb.WriteString(fmt.Sprintf("   %s\n", issue.Description))
// 				sb.WriteString(fmt.Sprintf("   Tool: %s", issue.Tool))
// 				if issue.Confidence != "" {
// 					sb.WriteString(fmt.Sprintf(" | Confidence: %s", issue.Confidence))
// 				}
// 				if issue.CWE != "" {
// 					sb.WriteString(fmt.Sprintf(" | CWE: %s", issue.CWE))
// 				}
// 				sb.WriteString("\n")
// 				if issue.Code != "" {
// 					sb.WriteString(fmt.Sprintf("   ```\n   %s\n   ```\n", issue.Code))
// 				}
// 				sb.WriteString("\n")
// 			}
// 		}

// 		sb.WriteString("```" + file.Language + "\n")
// 		sb.WriteString(file.Content)
// 		sb.WriteString("\n```\n\n")

// 		totalTokens += file.Tokens
// 		includedCount++
// 	}

// 	sb.WriteString("\n## Summary\n\n")
// 	sb.WriteString(fmt.Sprintf("- Files Included: %d / %d\n", includedCount, len(e.Files)))
// 	sb.WriteString(fmt.Sprintf("- Total Tokens: %d / %d\n", totalTokens, e.Config.MaxTotalTokens))

// 	return sb.String()
// }

// func (e *ContextEngine) countSecurityIssues() (critical, high, medium, low int) {
// 	for _, file := range e.Files {
// 		for _, issue := range file.Security {
// 			switch issue.Severity {
// 			case "CRITICAL":
// 				critical++
// 			case "HIGH":
// 				high++
// 			case "MEDIUM":
// 				medium++
// 			case "LOW":
// 				low++
// 			}
// 		}
// 	}
// 	return
// }

// func (e *ContextEngine) countIssuesByTool() map[string]int {
// 	counts := make(map[string]int)
// 	for _, file := range e.Files {
// 		for _, issue := range file.Security {
// 			counts[issue.Tool]++
// 		}
// 	}
// 	return counts
// }

// func (e *ContextEngine) getFileHash(path string) string {
// 	data := []byte(path)
// 	return fmt.Sprintf("%x", md5.Sum(data))
// }

// func estimateTokens(content string) int {
// 	return len(content) / 4
// }

// func detectLanguage(path string) string {
// 	ext := strings.ToLower(filepath.Ext(path))
// 	base := strings.ToLower(filepath.Base(path))

// 	// Check filename-based mappings first (e.g. Dockerfile, Makefile)
// 	fileNameMap := map[string]string{
// 		"dockerfile":       "dockerfile",
// 		"makefile":         "makefile",
// 		"gemfile":          "ruby",
// 		"rakefile":         "ruby",
// 		"podfile":          "ruby",
// 		"vagrantfile":      "ruby",
// 		"cmakelists.txt":   "cmake",
// 		"build.gradle":     "groovy",
// 		"build.gradle.kts": "kotlin",
// 	}
// 	if lang, ok := fileNameMap[base]; ok {
// 		return lang
// 	}

// 	langMap := map[string]string{
// 		// Systems
// 		".go":  "go",
// 		".c":   "c",
// 		".cpp": "cpp",
// 		".cc":  "cpp",
// 		".cxx": "cpp",
// 		".h":   "c",
// 		".hpp": "cpp",
// 		".hxx": "cpp",
// 		".rs":  "rust",
// 		".zig": "zig",
// 		".v":   "vlang",
// 		// JVM
// 		".java":   "java",
// 		".kt":     "kotlin",
// 		".kts":    "kotlin",
// 		".scala":  "scala",
// 		".groovy": "groovy",
// 		".clj":    "clojure",
// 		// Web / JS ecosystem
// 		".js":     "javascript",
// 		".mjs":    "javascript",
// 		".cjs":    "javascript",
// 		".jsx":    "javascript",
// 		".ts":     "typescript",
// 		".tsx":    "typescript",
// 		".html":   "html",
// 		".htm":    "html",
// 		".css":    "css",
// 		".scss":   "scss",
// 		".sass":   "sass",
// 		".less":   "less",
// 		".vue":    "vue",
// 		".svelte": "svelte",
// 		// Scripting
// 		".py":   "python",
// 		".rb":   "ruby",
// 		".php":  "php",
// 		".pl":   "perl",
// 		".pm":   "perl",
// 		".lua":  "lua",
// 		".sh":   "shell",
// 		".bash": "shell",
// 		".zsh":  "shell",
// 		".fish": "shell",
// 		".ps1":  "powershell",
// 		".psm1": "powershell",
// 		// Apple / mobile
// 		".swift": "swift",
// 		".m":     "objc",
// 		".mm":    "objcpp",
// 		".dart":  "dart",
// 		// .NET
// 		".cs":    "csharp",
// 		".fs":    "fsharp",
// 		".fsx":   "fsharp",
// 		".vb":    "vbnet",
// 		".axaml": "xml",
// 		".xaml":  "xml",
// 		// Data / config
// 		".sql": "sql",
// 		".r":   "r",
// 		".R":   "r",
// 		".jl":  "julia",
// 		".ex":  "elixir",
// 		".exs": "elixir",
// 		".erl": "erlang",
// 		".hrl": "erlang",
// 		".hs":  "haskell",
// 		".lhs": "haskell",
// 		".ml":  "ocaml",
// 		".mli": "ocaml",
// 		// Config / markup
// 		".json":    "json",
// 		".yaml":    "yaml",
// 		".yml":     "yaml",
// 		".toml":    "toml",
// 		".xml":     "xml",
// 		".md":      "markdown",
// 		".rst":     "rst",
// 		".tex":     "latex",
// 		".tf":      "terraform",
// 		".hcl":     "hcl",
// 		".proto":   "protobuf",
// 		".graphql": "graphql",
// 		".gql":     "graphql",
// 	}

// 	if lang, ok := langMap[ext]; ok {
// 		return lang
// 	}
// 	return "text"
// }

// func extractImports(content, lang string) []string {
// 	imports := make([]string, 0)
// 	switch lang {
// 	case "go":
// 		re := regexp.MustCompile(`import\s+(?:"([^"]+)"|([a-zA-Z0-9_/]+))`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			if m[1] != "" {
// 				imports = append(imports, m[1])
// 			}
// 		}
// 	case "python":
// 		re := regexp.MustCompile(`(?:from\s+(\S+)|import\s+(\S+))`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			if m[1] != "" {
// 				imports = append(imports, m[1])
// 			} else if m[2] != "" {
// 				imports = append(imports, m[2])
// 			}
// 		}
// 	case "javascript", "typescript":
// 		re := regexp.MustCompile(`import\s+.*?from\s+['"]([^'"]+)['"]`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			imports = append(imports, m[1])
// 		}
// 	case "java", "kotlin", "scala":
// 		re := regexp.MustCompile(`import\s+([\w.]+(?:\.\*)?)`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			imports = append(imports, m[1])
// 		}
// 	case "rust":
// 		re := regexp.MustCompile(`use\s+([\w:]+)`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			imports = append(imports, m[1])
// 		}
// 	case "swift":
// 		re := regexp.MustCompile(`import\s+(\w+)`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			imports = append(imports, m[1])
// 		}
// 	case "ruby":
// 		re := regexp.MustCompile(`require(?:_relative)?\s+['"]([^'"]+)['"]`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			imports = append(imports, m[1])
// 		}
// 	case "php":
// 		re := regexp.MustCompile(`(?:use|require|include)\s+['"]?([^'";]+)['"]?`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			imports = append(imports, strings.TrimSpace(m[1]))
// 		}
// 	case "lua":
// 		re := regexp.MustCompile(`require\s*\(?['"]([^'"]+)['"]\)?`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			imports = append(imports, m[1])
// 		}
// 	case "r":
// 		re := regexp.MustCompile(`(?:library|require)\s*\(\s*['"]?(\w+)['"]?\s*\)`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			imports = append(imports, m[1])
// 		}
// 	case "elixir":
// 		re := regexp.MustCompile(`(?:import|require|use|alias)\s+([\w.]+)`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			imports = append(imports, m[1])
// 		}
// 	}
// 	return imports
// }

// func extractFunctions(content, lang string) []string {
// 	functions := make([]string, 0)
// 	switch lang {
// 	case "go":
// 		re := regexp.MustCompile(`func\s+(\w+)\s*\(`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			functions = append(functions, m[1])
// 		}
// 	case "python":
// 		re := regexp.MustCompile(`def\s+(\w+)\s*\(`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			functions = append(functions, m[1])
// 		}
// 	case "javascript", "typescript":
// 		re := regexp.MustCompile(`function\s+(\w+)\s*\(|const\s+(\w+)\s*=\s*\([^)]*\)\s*=>`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			if m[1] != "" {
// 				functions = append(functions, m[1])
// 			} else if m[2] != "" {
// 				functions = append(functions, m[2])
// 			}
// 		}
// 	case "java", "kotlin":
// 		re := regexp.MustCompile(`(?:fun|void|public|private|protected|static|\w+)\s+(\w+)\s*\([^)]*\)\s*(?::\s*\w+)?\s*\{`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			functions = append(functions, m[1])
// 		}
// 	case "rust":
// 		re := regexp.MustCompile(`fn\s+(\w+)\s*\(`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			functions = append(functions, m[1])
// 		}
// 	case "swift":
// 		re := regexp.MustCompile(`func\s+(\w+)\s*\(`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			functions = append(functions, m[1])
// 		}
// 	case "ruby":
// 		re := regexp.MustCompile(`def\s+(\w+)`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			functions = append(functions, m[1])
// 		}
// 	case "php":
// 		re := regexp.MustCompile(`function\s+(\w+)\s*\(`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			functions = append(functions, m[1])
// 		}
// 	case "lua":
// 		re := regexp.MustCompile(`function\s+(\w+(?:\.\w+)*)\s*\(|local\s+function\s+(\w+)\s*\(`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			if m[1] != "" {
// 				functions = append(functions, m[1])
// 			} else if m[2] != "" {
// 				functions = append(functions, m[2])
// 			}
// 		}
// 	case "r":
// 		re := regexp.MustCompile(`(\w+)\s*<-\s*function\s*\(`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			functions = append(functions, m[1])
// 		}
// 	case "elixir":
// 		re := regexp.MustCompile(`def\s+(\w+)\s*[\(]`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			functions = append(functions, m[1])
// 		}
// 	case "scala":
// 		re := regexp.MustCompile(`def\s+(\w+)\s*[\([]`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			functions = append(functions, m[1])
// 		}
// 	case "csharp":
// 		re := regexp.MustCompile(`(?:public|private|protected|internal|static|virtual|override|async)\s+\w[\w<>\[\]]*\s+(\w+)\s*\(`)
// 		matches := re.FindAllStringSubmatch(content, -1)
// 		for _, m := range matches {
// 			functions = append(functions, m[1])
// 		}
// 	}
// 	return functions
// }

// func (e *ContextEngine) loadCache() {
// 	if e.Config.CacheDir == "" {
// 		return
// 	}
// 	cachePath := filepath.Join(e.Config.CacheDir, "context_cache.json")
// 	data, err := os.ReadFile(cachePath)
// 	if err != nil {
// 		return
// 	}
// 	json.Unmarshal(data, &e.Cache)
// }

// func (e *ContextEngine) saveCache() error {
// 	if !e.Config.CacheEnabled || e.Config.CacheDir == "" {
// 		return nil
// 	}
// 	os.MkdirAll(e.Config.CacheDir, 0755)
// 	cachePath := filepath.Join(e.Config.CacheDir, "context_cache.json")
// 	data, err := json.MarshalIndent(e.Cache, "", "  ")
// 	if err != nil {
// 		return err
// 	}
// 	return os.WriteFile(cachePath, data, 0644)
// }

// // nextDiffIndex finds the next available diff file index in cacheDir
// func nextDiffIndex(cacheDir string) int {
// 	entries, err := os.ReadDir(cacheDir)
// 	if err != nil {
// 		return 1
// 	}
// 	max := 0
// 	re := regexp.MustCompile(`^code_context_(\d+)\.(md|txt)$`)
// 	for _, entry := range entries {
// 		m := re.FindStringSubmatch(entry.Name())
// 		if m == nil {
// 			continue
// 		}
// 		n, _ := strconv.Atoi(m[1])
// 		if n > max {
// 			max = n
// 		}
// 	}
// 	return max + 1
// }

// // generateDiff compares old and new context strings and returns a markdown diff report.
// // It works at a file-section level: it finds added, removed, and changed file blocks.
// func generateDiff(oldCtx, newCtx string) string {
// 	oldFiles := parseFileSections(oldCtx)
// 	newFiles := parseFileSections(newCtx)

// 	var sb strings.Builder
// 	sb.WriteString("# Context Diff\n\n")
// 	sb.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().Format(time.RFC3339)))

// 	added := []string{}
// 	removed := []string{}
// 	changed := []string{}

// 	for path, newContent := range newFiles {
// 		if oldContent, exists := oldFiles[path]; !exists {
// 			added = append(added, path)
// 			_ = newContent
// 		} else if oldContent != newContent {
// 			changed = append(changed, path)
// 		}
// 	}
// 	for path := range oldFiles {
// 		if _, exists := newFiles[path]; !exists {
// 			removed = append(removed, path)
// 		}
// 	}

// 	sort.Strings(added)
// 	sort.Strings(removed)
// 	sort.Strings(changed)

// 	if len(added) == 0 && len(removed) == 0 && len(changed) == 0 {
// 		sb.WriteString("No changes detected since last run.\n")
// 		return sb.String()
// 	}

// 	sb.WriteString(fmt.Sprintf("Changes: +%d added, -%d removed, ~%d modified\n\n", len(added), len(removed), len(changed)))

// 	if len(added) > 0 {
// 		sb.WriteString("## Added Files\n\n")
// 		for _, path := range added {
// 			sb.WriteString(fmt.Sprintf("### %s\n\n", path))
// 			sb.WriteString(newFiles[path])
// 			sb.WriteString("\n\n")
// 		}
// 	}

// 	if len(removed) > 0 {
// 		sb.WriteString("## Removed Files\n\n")
// 		for _, path := range removed {
// 			sb.WriteString(fmt.Sprintf("- %s\n", path))
// 		}
// 		sb.WriteString("\n")
// 	}

// 	if len(changed) > 0 {
// 		sb.WriteString("## Modified Files\n\n")
// 		for _, path := range changed {
// 			sb.WriteString(fmt.Sprintf("### %s\n\n", path))
// 			sb.WriteString(lineDiff(oldFiles[path], newFiles[path]))
// 			sb.WriteString("\n\n")
// 		}
// 	}

// 	return sb.String()
// }

// // parseFileSections extracts per-file content blocks from a GenerateContext output.
// // Keys are the file paths, values are the full section text (header + body).
// func parseFileSections(ctx string) map[string]string {
// 	sections := make(map[string]string)
// 	lines := strings.Split(ctx, "\n")

// 	var currentPath string
// 	var currentLines []string

// 	reHeader := regexp.MustCompile(`^## File: (.+)$`)

// 	flush := func() {
// 		if currentPath != "" {
// 			sections[currentPath] = strings.Join(currentLines, "\n")
// 		}
// 	}

// 	for _, line := range lines {
// 		if m := reHeader.FindStringSubmatch(line); m != nil {
// 			flush()
// 			currentPath = strings.TrimSpace(m[1])
// 			currentLines = []string{line}
// 		} else if currentPath != "" {
// 			currentLines = append(currentLines, line)
// 		}
// 	}
// 	flush()
// 	return sections
// }

// // lineDiff produces a simple unified-style diff between two strings.
// func lineDiff(oldText, newText string) string {
// 	oldLines := strings.Split(oldText, "\n")
// 	newLines := strings.Split(newText, "\n")

// 	oldSet := make(map[string]bool, len(oldLines))
// 	newSet := make(map[string]bool, len(newLines))
// 	for _, l := range oldLines {
// 		oldSet[l] = true
// 	}
// 	for _, l := range newLines {
// 		newSet[l] = true
// 	}

// 	var sb strings.Builder
// 	sb.WriteString("```diff\n")
// 	for _, l := range oldLines {
// 		if !newSet[l] {
// 			sb.WriteString("- " + l + "\n")
// 		}
// 	}
// 	for _, l := range newLines {
// 		if !oldSet[l] {
// 			sb.WriteString("+ " + l + "\n")
// 		}
// 	}
// 	sb.WriteString("```\n")
// 	return sb.String()
// }

// func main() {
// 	// Parse flags
// 	forceRoot := false
// 	args := os.Args[1:]
// 	filtered := args[:0]
// 	for _, a := range args {
// 		if a == "-f" {
// 			forceRoot = true
// 		} else {
// 			filtered = append(filtered, a)
// 		}
// 	}
// 	args = filtered

// 	config := Config{
// 		MaxFileSize:    1000 * 1024,
// 		MaxTotalTokens: 10000000000,
// 		ExcludePatterns: []string{
// 			"node_modules", "vendor", ".git", "dist", "build",
// 			"__pycache__", ".pytest_cache", "target", ".next",
// 			"venv", ".venv", ".context_cache",
// 		},
// 		IncludeExtensions: []string{
// 			// Systems
// 			".go", ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx",
// 			".rs", ".zig", ".v",
// 			// JVM
// 			".java", ".kt", ".kts", ".scala", ".groovy", ".clj",
// 			// Web / JS ecosystem
// 			".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
// 			".html", ".htm", ".css", ".scss", ".sass", ".less",
// 			".vue", ".svelte",
// 			// Scripting
// 			".py", ".rb", ".php", ".pl", ".pm", ".lua",
// 			".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1",
// 			// Apple / mobile
// 			".swift", ".m", ".mm", ".dart",
// 			// .NET
// 			".cs", ".fs", ".fsx", ".vb", ".axaml", ".xaml",
// 			// Data / config languages
// 			".sql", ".r", ".R", ".jl", ".ex", ".exs",
// 			".erl", ".hrl", ".hs", ".lhs", ".ml", ".mli",
// 			// Config / markup
// 			".json", ".yaml", ".yml", ".toml", ".xml",
// 			".md", ".rst", ".tf", ".hcl", ".proto",
// 			".graphql", ".gql",
// 		},
// 		EnableSecurity: true,
// 		UseGosec:       true,
// 		UseBandit:      true,
// 		UseESLint:      true,
// 		UseFlawfinder:  true,
// 		UsePhpStan:     false,
// 		UseRubocop:     false,
// 		CacheEnabled:   true,
// 		CacheDir:       ".context_cache",
// 	}

// 	scanPath := "."
// 	if len(args) > 0 {
// 		scanPath = args[0]
// 	}

// 	absPath, err := filepath.Abs(scanPath)
// 	if err != nil {
// 		fmt.Fprintf(os.Stderr, "Error resolving path: %v\n", err)
// 		os.Exit(1)
// 	}

// 	if isRootDirectory(absPath) && !forceRoot {
// 		fmt.Fprintf(os.Stderr, "Error: refusing to scan the root directory (%s).\n", absPath)
// 		fmt.Fprintf(os.Stderr, "Use the -f flag to override: codeContext -f %s\n", scanPath)
// 		os.Exit(1)
// 	}

// 	engine := NewContextEngine(config)
// 	engine.CheckToolsAvailable()

// 	fmt.Printf("Scanning directory: %s\n\n", absPath)

// 	if err := engine.ScanDirectory(absPath); err != nil {
// 		fmt.Fprintf(os.Stderr, "Error scanning: %v\n", err)
// 		os.Exit(1)
// 	}

// 	fmt.Printf("Processed %d files\n\n", len(engine.Files))

// 	newContext := engine.GenerateContext()

// 	outputFile := "code_context.txt"

// 	// Load existing context for diff generation
// 	existingContext := ""
// 	if data, err := os.ReadFile(outputFile); err == nil {
// 		existingContext = string(data)
// 	}

// 	// Write updated code_context.txt
// 	if err := os.WriteFile(outputFile, []byte(newContext), 0644); err != nil {
// 		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
// 		os.Exit(1)
// 	}

// 	// Generate and write diff if a previous context exists
// 	if existingContext != "" {
// 		cacheDir := config.CacheDir
// 		os.MkdirAll(cacheDir, 0755)

// 		diffIndex := nextDiffIndex(cacheDir)
// 		diffContent := generateDiff(existingContext, newContext)
// 		diffFile := filepath.Join(cacheDir, fmt.Sprintf("code_context_%d.md", diffIndex))

// 		if err := os.WriteFile(diffFile, []byte(diffContent), 0644); err != nil {
// 			fmt.Fprintf(os.Stderr, "Warning: could not write diff file: %v\n", err)
// 		} else {
// 			fmt.Printf("Diff written to %s\n", diffFile)
// 		}
// 	}

// 	if err := engine.saveCache(); err != nil {
// 		fmt.Fprintf(os.Stderr, "Warning: could not save cache: %v\n", err)
// 	}

// 	fmt.Printf("Context written to %s\n\n", outputFile)

// 	if config.EnableSecurity {
// 		critical, high, medium, low := engine.countSecurityIssues()
// 		total := critical + high + medium + low
// 		if total > 0 {
// 			fmt.Printf("Security Issues Found: %d\n", total)
// 			fmt.Printf("  CRITICAL: %d | HIGH: %d | MEDIUM: %d | LOW: %d\n\n", critical, high, medium, low)

//				toolCounts := engine.countIssuesByTool()
//				fmt.Printf("Detection Tool Breakdown:\n")
//				for tool, count := range toolCounts {
//					if count > 0 {
//						fmt.Printf("  - %s: %d issues\n", tool, count)
//					}
//				}
//			} else {
//				fmt.Println("No security issues detected.")
//			}
//		}
//	}
package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Config holds engine configuration
type Config struct {
	MaxFileSize       int64    `json:"max_file_size"`
	MaxTotalTokens    int      `json:"max_total_tokens"`
	ExcludePatterns   []string `json:"exclude_patterns"`
	IncludeExtensions []string `json:"include_extensions"`
	CacheEnabled      bool     `json:"cache_enabled"`
	CacheDir          string   `json:"cache_dir"`
}

// FileContext represents a processed file
type FileContext struct {
	Path         string    `json:"path"`
	Content      string    `json:"content"`
	Hash         string    `json:"hash"`
	Size         int64     `json:"size"`
	Tokens       int       `json:"tokens"`
	ModifiedTime time.Time `json:"modified_time"`
	Language     string    `json:"language"`
	Imports      []string  `json:"imports"`
	Functions    []string  `json:"functions"`
}

// ContextEngine manages code context generation
type ContextEngine struct {
	Config      Config
	Files       []FileContext
	Cache       map[string]FileContext
	ProjectPath string
}

// NewContextEngine initializes the engine
func NewContextEngine(cfg Config) *ContextEngine {
	engine := &ContextEngine{
		Config: cfg,
		Files:  make([]FileContext, 0),
		Cache:  make(map[string]FileContext),
	}

	if cfg.CacheEnabled {
		engine.loadCache()
	}

	return engine
}

// isRootDirectory checks if a path is the OS root directory
func isRootDirectory(path string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absPath = filepath.Clean(absPath)

	if runtime.GOOS == "windows" {
		// On Windows, root looks like C:\ or D:\
		// filepath.VolumeName returns "C:" etc.
		vol := filepath.VolumeName(absPath)
		if vol == "" {
			return false
		}
		withSep := vol + string(filepath.Separator)
		return absPath == withSep || absPath == vol
	}

	return absPath == "/"
}

// ScanDirectory walks the directory and processes files
func (e *ContextEngine) ScanDirectory(root string) error {
	e.ProjectPath = root

	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if e.shouldExclude(path) {
				return filepath.SkipDir
			}
			return nil
		}

		if !e.shouldInclude(path) {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		if info.Size() > e.Config.MaxFileSize {
			return nil
		}

		relPath, _ := filepath.Rel(root, path)
		return e.processFile(path, relPath, info)
	})
}

func (e *ContextEngine) shouldExclude(path string) bool {
	base := filepath.Base(path)
	for _, pattern := range e.Config.ExcludePatterns {
		if base == pattern {
			return true
		}
	}
	return false
}

func (e *ContextEngine) shouldInclude(path string) bool {
	ext := filepath.Ext(path)
	for _, validExt := range e.Config.IncludeExtensions {
		if ext == validExt {
			return true
		}
	}
	return false
}

func (e *ContextEngine) processFile(path, relPath string, info fs.FileInfo) error {
	hash := e.getFileHash(path)

	if e.Config.CacheEnabled {
		if cached, exists := e.Cache[hash]; exists {
			if cached.ModifiedTime.Equal(info.ModTime()) {
				e.Files = append(e.Files, cached)
				return nil
			}
		}
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	relPath = strings.TrimPrefix(relPath, "./")
	relPath = strings.TrimPrefix(relPath, ":")

	ctx := FileContext{
		Path:         relPath,
		Content:      string(content),
		Hash:         hash,
		Size:         info.Size(),
		Tokens:       estimateTokens(string(content)),
		ModifiedTime: info.ModTime(),
		Language:     detectLanguage(path),
	}

	ctx.Imports = extractImports(ctx.Content, ctx.Language)
	ctx.Functions = extractFunctions(ctx.Content, ctx.Language)

	e.Files = append(e.Files, ctx)

	if e.Config.CacheEnabled {
		e.Cache[hash] = ctx
	}

	return nil
}

func (e *ContextEngine) GenerateContext() string {
	var sb strings.Builder
	totalTokens := 0

	sort.Slice(e.Files, func(i, j int) bool {
		return e.Files[i].Tokens > e.Files[j].Tokens
	})

	sb.WriteString("# Code Context\n")
	sb.WriteString(fmt.Sprintf("# Generated: %s\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("# Files: %d\n", len(e.Files)))
	sb.WriteString("#\n")
	sb.WriteString("# To extract all files back to disk, run:\n")
	sb.WriteString("#   awk '/^BEGIN_FILE:/{f=substr($0,11); sub(/^:/, \"\", f); next} /^END_FILE:/{f=\"\"; next} f{print > f}' code_context.txt\n")
	sb.WriteString("#\n")
	sb.WriteString("# To extract a single file, for example src/main.go, run:\n")
	sb.WriteString("#   awk '/^BEGIN_FILE:src\\/main\\.go$/{f=1;next}/^END_FILE:/{f=0}f' code_context.txt > src/main.go\n")
	sb.WriteString("#\n")

	includedCount := 0
	for _, file := range e.Files {
		if totalTokens+file.Tokens > e.Config.MaxTotalTokens {
			break
		}

		sb.WriteString(fmt.Sprintf("# path: %s | lang: %s | tokens: %d | size: %d\n", file.Path, file.Language, file.Tokens, file.Size))
		if len(file.Imports) > 0 {
			sb.WriteString(fmt.Sprintf("# imports: %s\n", strings.Join(file.Imports, ", ")))
		}
		if len(file.Functions) > 0 {
			sb.WriteString(fmt.Sprintf("# functions: %s\n", strings.Join(file.Functions, ", ")))
		}

		cleanPath := strings.TrimPrefix(strings.TrimPrefix(file.Path, "./"), ":")
		sb.WriteString(fmt.Sprintf("BEGIN_FILE:%s\n", cleanPath))
		sb.WriteString(file.Content)
		if len(file.Content) > 0 && file.Content[len(file.Content)-1] != '\n' {
			sb.WriteString("\n")
		}
		sb.WriteString(fmt.Sprintf("END_FILE:%s\n", cleanPath))

		totalTokens += file.Tokens
		includedCount++
	}

	sb.WriteString(fmt.Sprintf("# included: %d / %d | total tokens: %d\n", includedCount, len(e.Files), totalTokens))

	return sb.String()
}

func (e *ContextEngine) getFileHash(path string) string {
	data := []byte(path)
	return fmt.Sprintf("%x", md5.Sum(data))
}

func estimateTokens(content string) int {
	return len(content) / 4
}

func detectLanguage(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))

	// Check filename-based mappings first (e.g. Dockerfile, Makefile)
	fileNameMap := map[string]string{
		"dockerfile":       "dockerfile",
		"makefile":         "makefile",
		"gemfile":          "ruby",
		"rakefile":         "ruby",
		"podfile":          "ruby",
		"vagrantfile":      "ruby",
		"cmakelists.txt":   "cmake",
		"build.gradle":     "groovy",
		"build.gradle.kts": "kotlin",
	}
	if lang, ok := fileNameMap[base]; ok {
		return lang
	}

	langMap := map[string]string{
		// Systems
		".go":  "go",
		".c":   "c",
		".cpp": "cpp",
		".cc":  "cpp",
		".cxx": "cpp",
		".h":   "c",
		".hpp": "cpp",
		".hxx": "cpp",
		".rs":  "rust",
		".zig": "zig",
		".v":   "vlang",
		// JVM
		".java":   "java",
		".kt":     "kotlin",
		".kts":    "kotlin",
		".scala":  "scala",
		".groovy": "groovy",
		".clj":    "clojure",
		// Web / JS ecosystem
		".js":     "javascript",
		".mjs":    "javascript",
		".cjs":    "javascript",
		".jsx":    "javascript",
		".ts":     "typescript",
		".tsx":    "typescript",
		".html":   "html",
		".htm":    "html",
		".css":    "css",
		".scss":   "scss",
		".sass":   "sass",
		".less":   "less",
		".vue":    "vue",
		".svelte": "svelte",
		// Scripting
		".py":   "python",
		".rb":   "ruby",
		".php":  "php",
		".pl":   "perl",
		".pm":   "perl",
		".lua":  "lua",
		".sh":   "shell",
		".bash": "shell",
		".zsh":  "shell",
		".fish": "shell",
		".ps1":  "powershell",
		".psm1": "powershell",
		// Apple / mobile
		".swift": "swift",
		".m":     "objc",
		".mm":    "objcpp",
		".dart":  "dart",
		// .NET
		".cs":    "csharp",
		".fs":    "fsharp",
		".fsx":   "fsharp",
		".vb":    "vbnet",
		".axaml": "xml",
		".xaml":  "xml",
		// Data / config
		".sql": "sql",
		".r":   "r",
		".R":   "r",
		".jl":  "julia",
		".ex":  "elixir",
		".exs": "elixir",
		".erl": "erlang",
		".hrl": "erlang",
		".hs":  "haskell",
		".lhs": "haskell",
		".ml":  "ocaml",
		".mli": "ocaml",
		// Config / markup
		".json":    "json",
		".yaml":    "yaml",
		".yml":     "yaml",
		".toml":    "toml",
		".xml":     "xml",
		".md":      "markdown",
		".rst":     "rst",
		".tex":     "latex",
		".tf":      "terraform",
		".hcl":     "hcl",
		".proto":   "protobuf",
		".graphql": "graphql",
		".gql":     "graphql",
	}

	if lang, ok := langMap[ext]; ok {
		return lang
	}
	return "text"
}

func extractImports(content, lang string) []string {
	imports := make([]string, 0)
	switch lang {
	case "go":
		re := regexp.MustCompile(`import\s+(?:"([^"]+)"|([a-zA-Z0-9_/]+))`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if m[1] != "" {
				imports = append(imports, m[1])
			}
		}
	case "python":
		re := regexp.MustCompile(`(?:from\s+(\S+)|import\s+(\S+))`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if m[1] != "" {
				imports = append(imports, m[1])
			} else if m[2] != "" {
				imports = append(imports, m[2])
			}
		}
	case "javascript", "typescript":
		re := regexp.MustCompile(`import\s+.*?from\s+['"]([^'"]+)['"]`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			imports = append(imports, m[1])
		}
	case "java", "kotlin", "scala":
		re := regexp.MustCompile(`import\s+([\w.]+(?:\.\*)?)`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			imports = append(imports, m[1])
		}
	case "rust":
		re := regexp.MustCompile(`use\s+([\w:]+)`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			imports = append(imports, m[1])
		}
	case "swift":
		re := regexp.MustCompile(`import\s+(\w+)`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			imports = append(imports, m[1])
		}
	case "ruby":
		re := regexp.MustCompile(`require(?:_relative)?\s+['"]([^'"]+)['"]`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			imports = append(imports, m[1])
		}
	case "php":
		re := regexp.MustCompile(`(?:use|require|include)\s+['"]?([^'";]+)['"]?`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			imports = append(imports, strings.TrimSpace(m[1]))
		}
	case "lua":
		re := regexp.MustCompile(`require\s*\(?['"]([^'"]+)['"]\)?`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			imports = append(imports, m[1])
		}
	case "r":
		re := regexp.MustCompile(`(?:library|require)\s*\(\s*['"]?(\w+)['"]?\s*\)`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			imports = append(imports, m[1])
		}
	case "elixir":
		re := regexp.MustCompile(`(?:import|require|use|alias)\s+([\w.]+)`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			imports = append(imports, m[1])
		}
	}
	return imports
}

func extractFunctions(content, lang string) []string {
	functions := make([]string, 0)
	switch lang {
	case "go":
		re := regexp.MustCompile(`func\s+(\w+)\s*\(`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			functions = append(functions, m[1])
		}
	case "python":
		re := regexp.MustCompile(`def\s+(\w+)\s*\(`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			functions = append(functions, m[1])
		}
	case "javascript", "typescript":
		re := regexp.MustCompile(`function\s+(\w+)\s*\(|const\s+(\w+)\s*=\s*\([^)]*\)\s*=>`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if m[1] != "" {
				functions = append(functions, m[1])
			} else if m[2] != "" {
				functions = append(functions, m[2])
			}
		}
	case "java", "kotlin":
		re := regexp.MustCompile(`(?:fun|void|public|private|protected|static|\w+)\s+(\w+)\s*\([^)]*\)\s*(?::\s*\w+)?\s*\{`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			functions = append(functions, m[1])
		}
	case "rust":
		re := regexp.MustCompile(`fn\s+(\w+)\s*\(`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			functions = append(functions, m[1])
		}
	case "swift":
		re := regexp.MustCompile(`func\s+(\w+)\s*\(`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			functions = append(functions, m[1])
		}
	case "ruby":
		re := regexp.MustCompile(`def\s+(\w+)`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			functions = append(functions, m[1])
		}
	case "php":
		re := regexp.MustCompile(`function\s+(\w+)\s*\(`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			functions = append(functions, m[1])
		}
	case "lua":
		re := regexp.MustCompile(`function\s+(\w+(?:\.\w+)*)\s*\(|local\s+function\s+(\w+)\s*\(`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if m[1] != "" {
				functions = append(functions, m[1])
			} else if m[2] != "" {
				functions = append(functions, m[2])
			}
		}
	case "r":
		re := regexp.MustCompile(`(\w+)\s*<-\s*function\s*\(`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			functions = append(functions, m[1])
		}
	case "elixir":
		re := regexp.MustCompile(`def\s+(\w+)\s*[\(]`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			functions = append(functions, m[1])
		}
	case "scala":
		re := regexp.MustCompile(`def\s+(\w+)\s*[\([]`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			functions = append(functions, m[1])
		}
	case "csharp":
		re := regexp.MustCompile(`(?:public|private|protected|internal|static|virtual|override|async)\s+\w[\w<>\[\]]*\s+(\w+)\s*\(`)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			functions = append(functions, m[1])
		}
	}
	return functions
}

func (e *ContextEngine) loadCache() {
	if e.Config.CacheDir == "" {
		return
	}
	cachePath := filepath.Join(e.Config.CacheDir, "context_cache.json")
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return
	}
	json.Unmarshal(data, &e.Cache)
}

func (e *ContextEngine) saveCache() error {
	if !e.Config.CacheEnabled || e.Config.CacheDir == "" {
		return nil
	}
	os.MkdirAll(e.Config.CacheDir, 0755)
	cachePath := filepath.Join(e.Config.CacheDir, "context_cache.json")
	data, err := json.MarshalIndent(e.Cache, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cachePath, data, 0644)
}

// nextDiffIndex finds the next available diff file index in cacheDir
func nextDiffIndex(cacheDir string) int {
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return 1
	}
	max := 0
	re := regexp.MustCompile(`^code_context_(\d+)\.(md|txt)$`)
	for _, entry := range entries {
		m := re.FindStringSubmatch(entry.Name())
		if m == nil {
			continue
		}
		n, _ := strconv.Atoi(m[1])
		if n > max {
			max = n
		}
	}
	return max + 1
}

// generateDiff compares old and new context strings and returns a markdown diff report.
// It works at a file-section level: it finds added, removed, and changed file blocks.
func generateDiff(oldCtx, newCtx string) string {
	oldFiles := parseFileSections(oldCtx)
	newFiles := parseFileSections(newCtx)

	var sb strings.Builder
	sb.WriteString("# Context Diff\n\n")
	sb.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().Format(time.RFC3339)))

	added := []string{}
	removed := []string{}
	changed := []string{}

	for path, newContent := range newFiles {
		if oldContent, exists := oldFiles[path]; !exists {
			added = append(added, path)
			_ = newContent
		} else if oldContent != newContent {
			changed = append(changed, path)
		}
	}
	for path := range oldFiles {
		if _, exists := newFiles[path]; !exists {
			removed = append(removed, path)
		}
	}

	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)

	if len(added) == 0 && len(removed) == 0 && len(changed) == 0 {
		sb.WriteString("No changes detected since last run.\n")
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("Changes: +%d added, -%d removed, ~%d modified\n\n", len(added), len(removed), len(changed)))

	if len(added) > 0 {
		sb.WriteString("## Added Files\n\n")
		for _, path := range added {
			sb.WriteString(fmt.Sprintf("### %s\n\n", path))
			sb.WriteString(newFiles[path])
			sb.WriteString("\n\n")
		}
	}

	if len(removed) > 0 {
		sb.WriteString("## Removed Files\n\n")
		for _, path := range removed {
			sb.WriteString(fmt.Sprintf("- %s\n", path))
		}
		sb.WriteString("\n")
	}

	if len(changed) > 0 {
		sb.WriteString("## Modified Files\n\n")
		for _, path := range changed {
			sb.WriteString(fmt.Sprintf("### %s\n\n", path))
			sb.WriteString(lineDiff(oldFiles[path], newFiles[path]))
			sb.WriteString("\n\n")
		}
	}

	return sb.String()
}

// parseFileSections extracts per-file content blocks from a GenerateContext output.
// Keys are the file paths, values are the full section text (header + body).
func parseFileSections(ctx string) map[string]string {
	sections := make(map[string]string)
	lines := strings.Split(ctx, "\n")

	var currentPath string
	var currentLines []string

	reHeader := regexp.MustCompile(`^## File: (.+)$`)

	flush := func() {
		if currentPath != "" {
			sections[currentPath] = strings.Join(currentLines, "\n")
		}
	}

	for _, line := range lines {
		if m := reHeader.FindStringSubmatch(line); m != nil {
			flush()
			currentPath = strings.TrimSpace(m[1])
			currentLines = []string{line}
		} else if currentPath != "" {
			currentLines = append(currentLines, line)
		}
	}
	flush()
	return sections
}

// lineDiff produces a simple unified-style diff between two strings.
func lineDiff(oldText, newText string) string {
	oldLines := strings.Split(oldText, "\n")
	newLines := strings.Split(newText, "\n")

	oldSet := make(map[string]bool, len(oldLines))
	newSet := make(map[string]bool, len(newLines))
	for _, l := range oldLines {
		oldSet[l] = true
	}
	for _, l := range newLines {
		newSet[l] = true
	}

	var sb strings.Builder
	sb.WriteString("```diff\n")
	for _, l := range oldLines {
		if !newSet[l] {
			sb.WriteString("- " + l + "\n")
		}
	}
	for _, l := range newLines {
		if !oldSet[l] {
			sb.WriteString("+ " + l + "\n")
		}
	}
	sb.WriteString("```\n")
	return sb.String()
}

func main() {
	// Parse flags
	forceRoot := false
	args := os.Args[1:]
	filtered := args[:0]
	for _, a := range args {
		if a == "-f" {
			forceRoot = true
		} else {
			filtered = append(filtered, a)
		}
	}
	args = filtered

	config := Config{
		MaxFileSize:    1000 * 1024,
		MaxTotalTokens: 10000000000,
		ExcludePatterns: []string{
			"node_modules", "vendor", ".git", "dist", "build",
			"__pycache__", ".pytest_cache", "target", ".next",
			"venv", ".venv", ".context_cache",
		},
		IncludeExtensions: []string{
			// Systems
			".go", ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx",
			".rs", ".zig", ".v",
			// JVM
			".java", ".kt", ".kts", ".scala", ".groovy", ".clj",
			// Web / JS ecosystem
			".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
			".html", ".htm", ".css", ".scss", ".sass", ".less",
			".vue", ".svelte",
			// Scripting
			".py", ".rb", ".php", ".pl", ".pm", ".lua",
			".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1",
			// Apple / mobile
			".swift", ".m", ".mm", ".dart",
			// .NET
			".cs", ".fs", ".fsx", ".vb", ".axaml", ".xaml",
			// Data / config languages
			".sql", ".r", ".R", ".jl", ".ex", ".exs",
			".erl", ".hrl", ".hs", ".lhs", ".ml", ".mli",
			// Config / markup
			".json", ".yaml", ".yml", ".toml", ".xml",
			".md", ".rst", ".tf", ".hcl", ".proto",
			".graphql", ".gql",
		},
		CacheEnabled: true,
		CacheDir:     ".context_cache",
	}

	scanPath := "."
	if len(args) > 0 {
		scanPath = args[0]
	}

	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving path: %v\n", err)
		os.Exit(1)
	}

	if isRootDirectory(absPath) && !forceRoot {
		fmt.Fprintf(os.Stderr, "Error: refusing to scan the root directory (%s).\n", absPath)
		fmt.Fprintf(os.Stderr, "Use the -f flag to override: codeContext -f %s\n", scanPath)
		os.Exit(1)
	}

	engine := NewContextEngine(config)

	fmt.Printf("Scanning directory: %s\n\n", absPath)

	if err := engine.ScanDirectory(absPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Processed %d files\n\n", len(engine.Files))

	newContext := engine.GenerateContext()

	outputFile := "code_context.txt"

	// Load existing context for diff generation
	existingContext := ""
	if data, err := os.ReadFile(outputFile); err == nil {
		existingContext = string(data)
	}

	// Write updated code_context.txt
	if err := os.WriteFile(outputFile, []byte(newContext), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
		os.Exit(1)
	}

	// Generate and write diff if a previous context exists
	if existingContext != "" {
		cacheDir := config.CacheDir
		os.MkdirAll(cacheDir, 0755)

		diffIndex := nextDiffIndex(cacheDir)
		diffContent := generateDiff(existingContext, newContext)
		diffFile := filepath.Join(cacheDir, fmt.Sprintf("code_context_%d.md", diffIndex))

		if err := os.WriteFile(diffFile, []byte(diffContent), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not write diff file: %v\n", err)
		} else {
			fmt.Printf("Diff written to %s\n", diffFile)
		}
	}

	if err := engine.saveCache(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not save cache: %v\n", err)
	}

	fmt.Printf("Context written to %s\n\n", outputFile)
}
