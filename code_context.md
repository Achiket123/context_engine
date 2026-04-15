# Code Context Analysis

Generated: 2026-03-07T22:48:38+05:30
Files Scanned: 2
Analysis Tools: regex, gosec, eslint, flawfinder

## Security Summary

**Total Issues: 18**

- 🔴 CRITICAL: 2
- 🟠 HIGH: 0
- 🟡 MEDIUM: 7
- 🟢 LOW: 9

**Issues by Tool:**
- gosec: 12
- regex: 6

---

## File: main.go
Language: go | Tokens: 6859 | Size: 27437 bytes

**⚠️ Security Issues:**

🟡 **[MEDIUM]** Line 831 - G401
   *Use of weak cryptographic primitive*
   Tool: gosec | Confidence: HIGH | CWE: 328
   ```
   830: 	data := []byte(path)
831: 	return fmt.Sprintf("%x", md5.Sum(data))
832: }

   ```

🟡 **[MEDIUM]** Line 918 - G304
   *Potential file inclusion via variable*
   Tool: gosec | Confidence: HIGH | CWE: 22
   ```
   917: 	cachePath := filepath.Join(e.Config.CacheDir, "context_cache.json")
918: 	data, err := os.ReadFile(cachePath)
919: 	if err != nil {

   ```

🟡 **[MEDIUM]** Line 608 - G304
   *Potential file inclusion via variable*
   Tool: gosec | Confidence: HIGH | CWE: 22
   ```
   607: 
608: 	content, err := os.ReadFile(path)
609: 	if err != nil {

   ```

🟡 **[MEDIUM]** Line 929 - G301
   *Expect directory permissions to be 0750 or less*
   Tool: gosec | Confidence: HIGH | CWE: 276
   ```
   928: 	}
929: 	os.MkdirAll(e.Config.CacheDir, 0755)
930: 	cachePath := filepath.Join(e.Config.CacheDir, "context_cache.json")

   ```

🟡 **[MEDIUM]** Line 983 - G306
   *Expect WriteFile permissions to be 0600 or less*
   Tool: gosec | Confidence: HIGH | CWE: 276
   ```
   982: 	outputFile := "code_context.md"
983: 	if err := os.WriteFile(outputFile, []byte(context), 0644); err != nil {
984: 		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)

   ```

🟡 **[MEDIUM]** Line 935 - G306
   *Expect WriteFile permissions to be 0600 or less*
   Tool: gosec | Confidence: HIGH | CWE: 276
   ```
   934: 	}
935: 	return os.WriteFile(cachePath, data, 0644)
936: }

   ```

🟡 **[MEDIUM]** Line 5 - G501
   *Blocklisted import crypto/md5: weak cryptographic primitive*
   Tool: gosec | Confidence: HIGH | CWE: 327
   ```
   4: 	"bytes"
5: 	"crypto/md5"
6: 	"encoding/json"

   ```

🟢 **[LOW]** Line 929 - G104
   *Errors unhandled*
   Tool: gosec | Confidence: HIGH | CWE: 703
   ```
   928: 	}
929: 	os.MkdirAll(e.Config.CacheDir, 0755)
930: 	cachePath := filepath.Join(e.Config.CacheDir, "context_cache.json")

   ```

🟢 **[LOW]** Line 922 - G104
   *Errors unhandled*
   Tool: gosec | Confidence: HIGH | CWE: 703
   ```
   921: 	}
922: 	json.Unmarshal(data, &e.Cache)
923: }

   ```

🟢 **[LOW]** Line 489 - G104
   *Errors unhandled*
   Tool: gosec | Confidence: HIGH | CWE: 703
   ```
   488: 			fmt.Sscanf(matches[2], "%d", &lineNum)
489: 			fmt.Sscanf(matches[4], "%d", &level)
490: 

   ```

🟢 **[LOW]** Line 488 - G104
   *Errors unhandled*
   Tool: gosec | Confidence: HIGH | CWE: 703
   ```
   487: 			var lineNum, level int
488: 			fmt.Sscanf(matches[2], "%d", &lineNum)
489: 			fmt.Sscanf(matches[4], "%d", &level)

   ```

🟢 **[LOW]** Line 324 - G104
   *Errors unhandled*
   Tool: gosec | Confidence: HIGH | CWE: 703
   ```
   323: 		var line int
324: 		fmt.Sscanf(issue.Line, "%d", &line)
325: 

   ```

🔴 **[CRITICAL]** Line 170 - AWS Credentials
   *AWS credentials exposed*
   Tool: regex
   ```
   Pattern:     regexp.MustCompile(`(?i)(aws_access_key|aws_secret|AKIA[0-9A-Z]{16})`),
   ```

🔴 **[CRITICAL]** Line 178 - SQL Injection
   *Potential SQL injection vulnerability*
   Tool: regex
   ```
   Pattern:     regexp.MustCompile(`(execute|query|exec)\s*\([^)]*\+|fmt\.Sprintf.*SELECT|SELECT.*%s|"SELECT.*"\s*\+`),
   ```

🟢 **[LOW]** Line 263 - Debug Code
   *Debug code or security TODO in production*
   Tool: regex
   ```
   // Debug/Development code
   ```

🟢 **[LOW]** Line 265 - Debug Code
   *Debug code or security TODO in production*
   Tool: regex
   ```
   Pattern:     regexp.MustCompile(`(?i)(console\.log|print\(|var_dump|debug|TODO.*security|FIXME.*security)`),
   ```

🟢 **[LOW]** Line 266 - Debug Code
   *Debug code or security TODO in production*
   Tool: regex
   ```
   Type:        "Debug Code",
   ```

🟢 **[LOW]** Line 268 - Debug Code
   *Debug code or security TODO in production*
   Tool: regex
   ```
   Description: "Debug code or security TODO in production",
   ```

```go
package main

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Config holds engine configuration
type Config struct {
	MaxFileSize       int64    `json:"max_file_size"`
	MaxTotalTokens    int      `json:"max_total_tokens"`
	ExcludePatterns   []string `json:"exclude_patterns"`
	IncludeExtensions []string `json:"include_extensions"`
	EnableSecurity    bool     `json:"enable_security"`
	UseGosec          bool     `json:"use_gosec"`
	UseBandit         bool     `json:"use_bandit"`     // Python
	UseESLint         bool     `json:"use_eslint"`     // JavaScript/TypeScript
	UseFlawfinder     bool     `json:"use_flawfinder"` // C/C++
	UsePhpStan        bool     `json:"use_phpstan"`    // PHP
	UseRubocop        bool     `json:"use_rubocop"`    // Ruby
	CacheEnabled      bool     `json:"cache_enabled"`
	CacheDir          string   `json:"cache_dir"`
}

// FileContext represents a processed file
type FileContext struct {
	Path         string          `json:"path"`
	Content      string          `json:"content"`
	Hash         string          `json:"hash"`
	Size         int64           `json:"size"`
	Tokens       int             `json:"tokens"`
	ModifiedTime time.Time       `json:"modified_time"`
	Language     string          `json:"language"`
	Imports      []string        `json:"imports"`
	Functions    []string        `json:"functions"`
	Security     []SecurityIssue `json:"security,omitempty"`
}

// SecurityIssue represents a potential security threat
type SecurityIssue struct {
	Severity    string `json:"severity"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	File        string `json:"file"`
	Code        string `json:"code"`
	Tool        string `json:"tool"`
	CWE         string `json:"cwe,omitempty"`
	Confidence  string `json:"confidence,omitempty"`
}

// Tool output structures

// GosecIssue represents gosec JSON output
type GosecIssue struct {
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	RuleID     string `json:"rule_id"`
	Details    string `json:"details"`
	File       string `json:"file"`
	Code       string `json:"code"`
	Line       string `json:"line"`
	Column     string `json:"column"`
	CWE        struct {
		ID string `json:"id"`
	} `json:"cwe"`
}

type GosecOutput struct {
	Issues []GosecIssue `json:"Issues"`
}

// BanditResult represents bandit JSON output
type BanditResult struct {
	Results []struct {
		TestID          string `json:"test_id"`
		IssueConfidence string `json:"issue_confidence"`
		IssueSeverity   string `json:"issue_severity"`
		IssueText       string `json:"issue_text"`
		LineNumber      int    `json:"line_number"`
		Code            string `json:"code"`
		Filename        string `json:"filename"`
		CWE             struct {
			ID int `json:"id"`
		} `json:"cwe"`
	} `json:"results"`
}

// ESLintResult represents eslint JSON output
type ESLintResult []struct {
	FilePath string `json:"filePath"`
	Messages []struct {
		RuleID   string `json:"ruleId"`
		Severity int    `json:"severity"`
		Message  string `json:"message"`
		Line     int    `json:"line"`
		Column   int    `json:"column"`
	} `json:"messages"`
}

// FlawfinderResult represents flawfinder output
type FlawfinderHit struct {
	File        string
	Line        int
	Column      int
	Level       int
	Category    string
	Name        string
	Description string
	Code        string
}

// SecurityPattern defines regex-based security patterns
type SecurityPattern struct {
	Pattern     *regexp.Regexp
	Type        string
	Severity    string
	Description string
	Languages   []string
}

// ContextEngine manages code context generation
type ContextEngine struct {
	Config      Config
	Files       []FileContext
	Cache       map[string]FileContext
	SecurityDB  []SecurityPattern
	ProjectPath string
}

// NewContextEngine initializes the engine
func NewContextEngine(cfg Config) *ContextEngine {
	engine := &ContextEngine{
		Config:     cfg,
		Files:      make([]FileContext, 0),
		Cache:      make(map[string]FileContext),
		SecurityDB: initSecurityPatterns(),
	}

	if cfg.CacheEnabled {
		engine.loadCache()
	}

	return engine
}

// initSecurityPatterns defines comprehensive multi-language patterns
func initSecurityPatterns() []SecurityPattern {
	patterns := []SecurityPattern{
		// Credentials - All languages
		{
			Pattern:     regexp.MustCompile(`(?i)(password|passwd|pwd|secret|api_key|apikey|token|private_key)\s*=\s*["'][^"']{8,}["']`),
			Type:        "Hardcoded Credentials",
			Severity:    "CRITICAL",
			Description: "Hardcoded credentials detected",
			Languages:   []string{"*"},
		},
		{
			Pattern:     regexp.MustCompile(`(?i)(aws_access_key|aws_secret|AKIA[0-9A-Z]{16})`),
			Type:        "AWS Credentials",
			Severity:    "CRITICAL",
			Description: "AWS credentials exposed",
			Languages:   []string{"*"},
		},
		// SQL Injection - Multiple languages
		{
			Pattern:     regexp.MustCompile(`(execute|query|exec)\s*\([^)]*\+|fmt\.Sprintf.*SELECT|SELECT.*%s|"SELECT.*"\s*\+`),
			Type:        "SQL Injection",
			Severity:    "CRITICAL",
			Description: "Potential SQL injection vulnerability",
			Languages:   []string{"go", "python", "javascript", "typescript", "php", "java"},
		},
		// Command Injection
		{
			Pattern:     regexp.MustCompile(`(exec\.Command|os\.system|subprocess\.call|eval|shell_exec|system)\s*\([^)]*\+`),
			Type:        "Command Injection",
			Severity:    "HIGH",
			Description: "Dynamic command construction - potential command injection",
			Languages:   []string{"go", "python", "javascript", "php", "ruby"},
		},
		// XSS vulnerabilities
		{
			Pattern:     regexp.MustCompile(`innerHTML\s*=|document\.write\(|\.html\([^)]*\+`),
			Type:        "XSS Vulnerability",
			Severity:    "HIGH",
			Description: "Potential XSS - dynamic HTML content",
			Languages:   []string{"javascript", "typescript"},
		},
		// Path Traversal
		{
			Pattern:     regexp.MustCompile(`(os\.Open|ioutil\.ReadFile|open\(|file_get_contents|readFile)\s*\([^)]*\+`),
			Type:        "Path Traversal",
			Severity:    "HIGH",
			Description: "Dynamic file path - potential path traversal",
			Languages:   []string{"go", "python", "javascript", "php", "ruby"},
		},
		// Weak Crypto
		{
			Pattern:     regexp.MustCompile(`(MD5|SHA1|DES|RC4|md5|sha1)\s*\(`),
			Type:        "Weak Cryptography",
			Severity:    "MEDIUM",
			Description: "Use of weak cryptographic algorithm",
			Languages:   []string{"*"},
		},
		{
			Pattern:     regexp.MustCompile(`Math\.random|rand\(\)|mt_rand\(\)`),
			Type:        "Weak Random",
			Severity:    "MEDIUM",
			Description: "Weak random number generator for security",
			Languages:   []string{"javascript", "php", "c", "cpp"},
		},
		// Deserialization
		{
			Pattern:     regexp.MustCompile(`(pickle\.loads|yaml\.load|unserialize|eval\(|json\.loads.*JSONDecoder)`),
			Type:        "Unsafe Deserialization",
			Severity:    "HIGH",
			Description: "Unsafe deserialization of untrusted data",
			Languages:   []string{"python", "php", "javascript", "ruby"},
		},
		// SSRF
		{
			Pattern:     regexp.MustCompile(`(http\.Get|requests\.get|fetch|curl_exec|Net::HTTP)\s*\([^)]*\+`),
			Type:        "SSRF",
			Severity:    "HIGH",
			Description: "Server-Side Request Forgery risk",
			Languages:   []string{"go", "python", "javascript", "php", "ruby"},
		},
		// Code Injection
		{
			Pattern:     regexp.MustCompile(`\beval\s*\(|exec\s*\(|Function\s*\(`),
			Type:        "Code Injection",
			Severity:    "CRITICAL",
			Description: "Dynamic code execution",
			Languages:   []string{"javascript", "python", "php"},
		},
		// Buffer Overflow - C/C++
		{
			Pattern:     regexp.MustCompile(`\b(gets|strcpy|strcat|sprintf|vsprintf)\s*\(`),
			Type:        "Buffer Overflow",
			Severity:    "CRITICAL",
			Description: "Unsafe buffer function",
			Languages:   []string{"c", "cpp"},
		},
		// XXE - XML External Entity
		{
			Pattern:     regexp.MustCompile(`XMLParser|parseXML|DocumentBuilder.*parse|simplexml_load`),
			Type:        "XXE Risk",
			Severity:    "HIGH",
			Description: "XML parser may be vulnerable to XXE",
			Languages:   []string{"java", "php", "python", "javascript"},
		},
		// Debug/Development code
		{
			Pattern:     regexp.MustCompile(`(?i)(console\.log|print\(|var_dump|debug|TODO.*security|FIXME.*security)`),
			Type:        "Debug Code",
			Severity:    "LOW",
			Description: "Debug code or security TODO in production",
			Languages:   []string{"*"},
		},
	}

	return patterns
}

// CheckToolsAvailable verifies required tools are installed
func (e *ContextEngine) CheckToolsAvailable() {
	tools := map[string]*bool{
		"gosec":      &e.Config.UseGosec,
		"bandit":     &e.Config.UseBandit,
		"eslint":     &e.Config.UseESLint,
		"flawfinder": &e.Config.UseFlawfinder,
		"phpstan":    &e.Config.UsePhpStan,
		"rubocop":    &e.Config.UseRubocop,
	}

	fmt.Println("Checking available security tools:")
	for tool, enabled := range tools {
		if *enabled {
			if _, err := exec.LookPath(tool); err != nil {
				fmt.Printf("⚠️  %s not found (disabled)\n", tool)
				*enabled = false
			} else {
				fmt.Printf("✓ %s found\n", tool)
			}
		}
	}
	fmt.Println()
}

// RunGosec executes gosec on Go files
func (e *ContextEngine) RunGosec() ([]SecurityIssue, error) {
	if !e.Config.UseGosec {
		return nil, nil
	}

	fmt.Println("Running gosec analysis...")
	cmd := exec.Command("gosec", "-fmt=json", "-quiet", "./...")
	cmd.Dir = e.ProjectPath

	output, _ := cmd.CombinedOutput()
	if len(output) == 0 {
		return nil, nil
	}

	var result GosecOutput
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse gosec output: %v", err)
	}

	issues := make([]SecurityIssue, 0)
	for _, issue := range result.Issues {
		var line int
		fmt.Sscanf(issue.Line, "%d", &line)

		relPath, _ := filepath.Rel(e.ProjectPath, issue.File)

		issues = append(issues, SecurityIssue{
			Severity:    strings.ToUpper(issue.Severity),
			Type:        issue.RuleID,
			Description: issue.Details,
			Line:        line,
			File:        relPath,
			Code:        issue.Code,
			Tool:        "gosec",
			CWE:         issue.CWE.ID,
			Confidence:  issue.Confidence,
		})
	}

	fmt.Printf("  Found %d issues with gosec\n", len(issues))
	return issues, nil
}

// RunBandit executes bandit on Python files
func (e *ContextEngine) RunBandit() ([]SecurityIssue, error) {
	if !e.Config.UseBandit {
		return nil, nil
	}

	fmt.Println("Running bandit analysis...")
	cmd := exec.Command("bandit", "-r", ".", "-f", "json", "-q")
	cmd.Dir = e.ProjectPath

	output, _ := cmd.CombinedOutput()
	if len(output) == 0 {
		return nil, nil
	}

	var result BanditResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse bandit output: %v", err)
	}

	issues := make([]SecurityIssue, 0)
	for _, finding := range result.Results {
		relPath, _ := filepath.Rel(e.ProjectPath, finding.Filename)

		severity := strings.ToUpper(finding.IssueSeverity)
		if severity == "UNDEFINED" {
			severity = "MEDIUM"
		}

		cwe := ""
		if finding.CWE.ID > 0 {
			cwe = fmt.Sprintf("CWE-%d", finding.CWE.ID)
		}

		issues = append(issues, SecurityIssue{
			Severity:    severity,
			Type:        finding.TestID,
			Description: finding.IssueText,
			Line:        finding.LineNumber,
			File:        relPath,
			Code:        finding.Code,
			Tool:        "bandit",
			CWE:         cwe,
			Confidence:  finding.IssueConfidence,
		})
	}

	fmt.Printf("  Found %d issues with bandit\n", len(issues))
	return issues, nil
}

// RunESLint executes eslint with security plugin
func (e *ContextEngine) RunESLint() ([]SecurityIssue, error) {
	if !e.Config.UseESLint {
		return nil, nil
	}

	fmt.Println("Running eslint analysis...")
	cmd := exec.Command("eslint", ".", "--ext", ".js,.jsx,.ts,.tsx", "-f", "json")
	cmd.Dir = e.ProjectPath

	output, _ := cmd.CombinedOutput()
	if len(output) == 0 {
		return nil, nil
	}

	idx := bytes.IndexByte(output, '[')
	if idx == -1 {
		return nil, fmt.Errorf("failed to parse eslint output: no JSON array found")
	}
	output = output[idx:]

	var result ESLintResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse eslint output: %v", err)
	}

	issues := make([]SecurityIssue, 0)
	for _, file := range result {
		relPath, _ := filepath.Rel(e.ProjectPath, file.FilePath)

		for _, msg := range file.Messages {
			if msg.RuleID == "" || msg.Severity < 1 {
				continue
			}

			// Only include security-related rules
			if !strings.Contains(msg.RuleID, "security") &&
				!strings.Contains(msg.RuleID, "no-eval") &&
				!strings.Contains(msg.RuleID, "no-implied-eval") {
				continue
			}

			severity := "MEDIUM"
			if msg.Severity == 2 {
				severity = "HIGH"
			}

			issues = append(issues, SecurityIssue{
				Severity:    severity,
				Type:        msg.RuleID,
				Description: msg.Message,
				Line:        msg.Line,
				Column:      msg.Column,
				File:        relPath,
				Tool:        "eslint",
			})
		}
	}

	fmt.Printf("  Found %d issues with eslint\n", len(issues))
	return issues, nil
}

// RunFlawfinder executes flawfinder on C/C++ files
func (e *ContextEngine) RunFlawfinder() ([]SecurityIssue, error) {
	if !e.Config.UseFlawfinder {
		return nil, nil
	}

	fmt.Println("Running flawfinder analysis...")
	cmd := exec.Command("flawfinder", "--quiet", "--dataonly", ".")
	cmd.Dir = e.ProjectPath

	output, _ := cmd.CombinedOutput()
	if len(output) == 0 {
		return nil, nil
	}

	issues := make([]SecurityIssue, 0)
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		// Parse flawfinder output: file:line:column: [level] category: description
		re := regexp.MustCompile(`([^:]+):(\d+):(\d+):\s*\[(\d+)\]\s*\(([^)]+)\)\s*(.+)`)
		matches := re.FindStringSubmatch(line)

		if len(matches) == 7 {
			var lineNum, level int
			fmt.Sscanf(matches[2], "%d", &lineNum)
			fmt.Sscanf(matches[4], "%d", &level)

			severity := "LOW"
			if level >= 4 {
				severity = "HIGH"
			} else if level >= 2 {
				severity = "MEDIUM"
			}

			relPath, _ := filepath.Rel(e.ProjectPath, matches[1])

			issues = append(issues, SecurityIssue{
				Severity:    severity,
				Type:        matches[5],
				Description: matches[6],
				Line:        lineNum,
				File:        relPath,
				Tool:        "flawfinder",
			})
		}
	}

	fmt.Printf("  Found %d issues with flawfinder\n", len(issues))
	return issues, nil
}

// ScanDirectory walks the directory and processes files
func (e *ContextEngine) ScanDirectory(root string) error {
	e.ProjectPath = root

	// Run security tools on entire project
	var allSecurityIssues []SecurityIssue

	if e.Config.EnableSecurity {
		tools := []func() ([]SecurityIssue, error){
			e.RunGosec,
			e.RunBandit,
			e.RunESLint,
			e.RunFlawfinder,
		}

		for _, tool := range tools {
			if issues, err := tool(); err != nil {
				fmt.Printf("Warning: %v\n", err)
			} else {
				allSecurityIssues = append(allSecurityIssues, issues...)
			}
		}
	}

	// Create map for quick lookup of security issues by file
	securityByFile := make(map[string][]SecurityIssue)
	for _, issue := range allSecurityIssues {
		securityByFile[issue.File] = append(securityByFile[issue.File], issue)
	}

	// Walk directory and process files
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
		return e.processFile(path, relPath, info, securityByFile[relPath])
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

func (e *ContextEngine) processFile(path, relPath string, info fs.FileInfo, fileIssues []SecurityIssue) error {
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

	ctx := FileContext{
		Path:         relPath,
		Content:      string(content),
		Hash:         hash,
		Size:         info.Size(),
		Tokens:       estimateTokens(string(content)),
		ModifiedTime: info.ModTime(),
		Language:     detectLanguage(path),
		Security:     make([]SecurityIssue, 0),
	}

	ctx.Imports = extractImports(ctx.Content, ctx.Language)
	ctx.Functions = extractFunctions(ctx.Content, ctx.Language)

	// Match security issues to this file
	if fileIssues != nil {
		ctx.Security = append(ctx.Security, fileIssues...)
	}

	// Add regex-based analysis
	if e.Config.EnableSecurity {
		regexIssues := e.analyzeSecurityThreatsRegex(ctx.Content, ctx.Language)
		ctx.Security = append(ctx.Security, regexIssues...)
	}

	e.Files = append(e.Files, ctx)

	if e.Config.CacheEnabled {
		e.Cache[hash] = ctx
	}

	return nil
}

func (e *ContextEngine) analyzeSecurityThreatsRegex(content, lang string) []SecurityIssue {
	issues := make([]SecurityIssue, 0)
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		for _, pattern := range e.SecurityDB {
			// Check if pattern applies to this language
			if !e.patternApplies(pattern, lang) {
				continue
			}

			if pattern.Pattern.MatchString(line) {
				issues = append(issues, SecurityIssue{
					Severity:    pattern.Severity,
					Type:        pattern.Type,
					Description: pattern.Description,
					Line:        i + 1,
					Code:        strings.TrimSpace(line),
					Tool:        "regex",
				})
			}
		}
	}

	return issues
}

func (e *ContextEngine) patternApplies(pattern SecurityPattern, lang string) bool {
	for _, l := range pattern.Languages {
		if l == "*" || l == lang {
			return true
		}
	}
	return false
}

func (e *ContextEngine) GenerateContext() string {
	var sb strings.Builder
	totalTokens := 0

	sort.Slice(e.Files, func(i, j int) bool {
		if len(e.Files[i].Security) != len(e.Files[j].Security) {
			return len(e.Files[i].Security) > len(e.Files[j].Security)
		}
		return e.Files[i].Tokens > e.Files[j].Tokens
	})

	sb.WriteString("# Code Context Analysis\n\n")
	sb.WriteString(fmt.Sprintf("Generated: %s\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Files Scanned: %d\n", len(e.Files)))

	tools := []string{"regex"}
	if e.Config.UseGosec {
		tools = append(tools, "gosec")
	}
	if e.Config.UseBandit {
		tools = append(tools, "bandit")
	}
	if e.Config.UseESLint {
		tools = append(tools, "eslint")
	}
	if e.Config.UseFlawfinder {
		tools = append(tools, "flawfinder")
	}
	sb.WriteString(fmt.Sprintf("Analysis Tools: %s\n\n", strings.Join(tools, ", ")))

	if e.Config.EnableSecurity {
		sb.WriteString("## Security Summary\n\n")
		critical, high, medium, low := e.countSecurityIssues()
		total := critical + high + medium + low

		sb.WriteString(fmt.Sprintf("**Total Issues: %d**\n\n", total))
		sb.WriteString(fmt.Sprintf("- 🔴 CRITICAL: %d\n", critical))
		sb.WriteString(fmt.Sprintf("- 🟠 HIGH: %d\n", high))
		sb.WriteString(fmt.Sprintf("- 🟡 MEDIUM: %d\n", medium))
		sb.WriteString(fmt.Sprintf("- 🟢 LOW: %d\n\n", low))

		toolCounts := e.countIssuesByTool()
		sb.WriteString("**Issues by Tool:**\n")
		for tool, count := range toolCounts {
			if count > 0 {
				sb.WriteString(fmt.Sprintf("- %s: %d\n", tool, count))
			}
		}
		sb.WriteString("\n")
	}

	sb.WriteString("---\n\n")

	includedCount := 0
	for _, file := range e.Files {
		if totalTokens+file.Tokens > e.Config.MaxTotalTokens {
			break
		}

		sb.WriteString(fmt.Sprintf("## File: %s\n", file.Path))
		sb.WriteString(fmt.Sprintf("Language: %s | Tokens: %d | Size: %d bytes\n\n", file.Language, file.Tokens, file.Size))

		if len(file.Imports) > 0 {
			sb.WriteString("**Imports:** " + strings.Join(file.Imports, ", ") + "\n\n")
		}

		if len(file.Security) > 0 {
			sb.WriteString("**⚠️ Security Issues:**\n\n")
			for _, issue := range file.Security {
				emoji := getSeverityEmoji(issue.Severity)
				sb.WriteString(fmt.Sprintf("%s **[%s]** Line %d - %s\n", emoji, issue.Severity, issue.Line, issue.Type))
				sb.WriteString(fmt.Sprintf("   *%s*\n", issue.Description))
				sb.WriteString(fmt.Sprintf("   Tool: %s", issue.Tool))
				if issue.Confidence != "" {
					sb.WriteString(fmt.Sprintf(" | Confidence: %s", issue.Confidence))
				}
				if issue.CWE != "" {
					sb.WriteString(fmt.Sprintf(" | CWE: %s", issue.CWE))
				}
				sb.WriteString("\n")
				if issue.Code != "" {
					sb.WriteString(fmt.Sprintf("   ```\n   %s\n   ```\n", issue.Code))
				}
				sb.WriteString("\n")
			}
		}

		sb.WriteString("```" + file.Language + "\n")
		sb.WriteString(file.Content)
		sb.WriteString("\n```\n\n")

		totalTokens += file.Tokens
		includedCount++
	}

	sb.WriteString("\n---\n\n")
	sb.WriteString(fmt.Sprintf("**Summary:**\n"))
	sb.WriteString(fmt.Sprintf("- Files Included: %d / %d\n", includedCount, len(e.Files)))
	sb.WriteString(fmt.Sprintf("- Total Tokens: %d / %d\n", totalTokens, e.Config.MaxTotalTokens))

	return sb.String()
}

func getSeverityEmoji(severity string) string {
	switch severity {
	case "CRITICAL":
		return "🔴"
	case "HIGH":
		return "🟠"
	case "MEDIUM":
		return "🟡"
	case "LOW":
		return "🟢"
	default:
		return "⚪"
	}
}

func (e *ContextEngine) countSecurityIssues() (critical, high, medium, low int) {
	for _, file := range e.Files {
		for _, issue := range file.Security {
			switch issue.Severity {
			case "CRITICAL":
				critical++
			case "HIGH":
				high++
			case "MEDIUM":
				medium++
			case "LOW":
				low++
			}
		}
	}
	return
}

func (e *ContextEngine) countIssuesByTool() map[string]int {
	counts := make(map[string]int)
	for _, file := range e.Files {
		for _, issue := range file.Security {
			counts[issue.Tool]++
		}
	}
	return counts
}

func (e *ContextEngine) getFileHash(path string) string {
	data := []byte(path)
	return fmt.Sprintf("%x", md5.Sum(data))
}

func estimateTokens(content string) int {
	return len(content) / 4
}

func detectLanguage(path string) string {
	ext := filepath.Ext(path)
	langMap := map[string]string{
		".go": "go", ".js": "javascript", ".ts": "typescript",
		".py": "python", ".java": "java", ".rs": "rust",
		".c": "c", ".cpp": "cpp", ".h": "c", ".hpp": "cpp",
		".html": "html", ".css": "css", ".rb": "ruby", ".php": "php",
		".dart": "dart", ".mjs": "javascript", ".sh": "shell",
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

func main() {
	config := Config{
		MaxFileSize:    100 * 1024,
		MaxTotalTokens: 100000,
		ExcludePatterns: []string{
			"node_modules", "vendor", ".git", "dist", "build",
			"__pycache__", ".pytest_cache", "target", ".next",
			"venv",
		},
		IncludeExtensions: []string{
			".go", ".js", ".ts", ".py", ".java", ".rs",
			".c", ".cpp", ".h", ".css", ".html", ".rb", ".php", ".dart", ".mjs", ".sh",
		},
		EnableSecurity: true,
		UseGosec:       true,
		UseBandit:      true,
		UseESLint:      true,
		UseFlawfinder:  true,
		UsePhpStan:     false,
		UseRubocop:     false,
		CacheEnabled:   true,
		CacheDir:       ".context_cache",
	}

	engine := NewContextEngine(config)
	engine.CheckToolsAvailable()

	scanPath := "."
	if len(os.Args) > 1 {
		scanPath = os.Args[1]
	}

	absPath, _ := filepath.Abs(scanPath)
	fmt.Printf("\n🔍 Scanning directory: %s\n\n", absPath)

	if err := engine.ScanDirectory(absPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n✓ Processed %d files\n\n", len(engine.Files))

	context := engine.GenerateContext()

	outputFile := "code_context.md"
	if err := os.WriteFile(outputFile, []byte(context), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
		os.Exit(1)
	}

	if err := engine.saveCache(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not save cache: %v\n", err)
	}

	fmt.Printf("📄 Context written to %s\n\n", outputFile)

	if config.EnableSecurity {
		critical, high, medium, low := engine.countSecurityIssues()
		total := critical + high + medium + low
		if total > 0 {
			fmt.Printf("⚠️  Security Issues Found: %d\n", total)
			fmt.Printf("   🔴 CRITICAL: %d | 🟠 HIGH: %d | 🟡 MEDIUM: %d | 🟢 LOW: %d\n\n", critical, high, medium, low)

			toolCounts := engine.countIssuesByTool()
			fmt.Printf("📊 Detection Tool Breakdown:\n")
			for tool, count := range toolCounts {
				if count > 0 {
					fmt.Printf("   - %s: %d issues\n", tool, count)
				}
			}
		} else {
			fmt.Println("✅ No security issues detected!")
		}
	}
}

```

## File: index.html
Language: html | Tokens: 435 | Size: 1741 bytes

```html
<!DOCTYPE html>
<html>
<head>
  <!-- ... (keep existing meta tags and base href) ... -->
  <base href="/">
    <link rel="icon" type="image/png" href="/favicon-96x96.png" sizes="96x96" />
<link rel="icon" type="image/svg+xml" href="/favicon.svg" />
<link rel="shortcut icon" href="/favicon.ico" />
<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
<link rel="manifest" href="/site.webmanifest" />
  <meta charset="UTF-8">
  <meta content="IE-Edge" http-equiv="X-UA-Compatible">
  <meta name="description" content="A new Flutter project.">

  <!-- iOS meta tags & icons -->
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black">
  <meta name="apple-mobile-web-app-title" content="portfolio">
  <link rel="apple-touch-icon" href="icons/Icon-192.png">

  <!-- Favicon -->
  <link rel="icon" type="image/png" href="favicon.png"/>

  <title>portfolio</title>
  <link rel="manifest" href="manifest.json">

  <!-- ADD THIS STYLE BLOCK -->
  <style>
    /* Make the body background transparent so the canvas shows through */
    body {
      background-color: transparent;
    }
    /* Style for our background canvas */
    #matrix-canvas {
      position: fixed; /* Stick to the viewport */
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      z-index: -1; /* CRITICAL: Puts the canvas behind the Flutter app */
    }
  </style>
</head>
<body>
  <!-- ADD THE CANVAS ELEMENT HERE -->
  <canvas id="matrix-canvas"></canvas>

  <!-- This is the standard Flutter script -->
  <script src="flutter_bootstrap.js" async></script>

  <!-- ADD THE SCRIPT FOR OUR ANIMATION HERE -->
  <script src="matrix.js"></script>
</body>
</html>

```


---

**Summary:**
- Files Included: 2 / 2
- Total Tokens: 7294 / 100000
