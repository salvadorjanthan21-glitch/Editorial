---
tags: [log-analysis]
---

# Searching and Filtering Logs with Regex and KQL

## TCM Exam Objectives

By mastering this module, you will be prepared to:

1. **Construct** KQL queries using the pipeline architecture (where, project, summarize, join)
2. **Apply** time filters using `ago()` to scope investigations to relevant windows
3. **Write** RE2-compatible regular expressions for pattern matching in log data
4. **Extract** structured fields from raw logs using `extract()` with capture groups
5. **Use** the `parse` operator to decompose syslog messages and custom formats
6. **Optimize** query performance by filtering by time first and using `has` over `contains`
7. **Demonstrate** double-escaped regex strings in KQL (`\\d` not `\d`)
8. **Correlate** threat intelligence indicators using `matches regex` and `summarize`
9. **Build** an end-to-end investigation query from alert to root cause
10. **Interpret** regex capture group limitations (max 16 groups in KQL)

Kusto Query Language (KQL) and regular expressions are essential tools for searching, filtering, and extracting data from massive log datasets in Microsoft Sentinel and Azure Monitor. The PSAA exam drops you into a realistic SOC environment where you must triage alerts and identify IOCs across multiple tables. Mastering these query languages directly determines how quickly you can isolate malicious activity.

- KQL core operators and pipeline architecture
- Regular expression fundamentals for log matching
- Extracting structured data with `extract()` and `parse`
- Practical investigation scenarios

```mermaid
flowchart LR
    A[Raw Log Data] --> B[Time Filter: ago()]
    B --> C[Where: filter by condition]
    C --> D[Project: select columns]
    D --> E[Summarize: aggregate counts]
    E --> F[Order by: sort results]
    F --> G[Take: limit output]
    
    C --> H[matches regex: pattern filter]
    H --> I[extract(): capture groups]
    I --> J[extend: new calculated columns]
```

📌 **Exam Tip:** Always filter by time first (`where TimeGenerated > ago(24h)`) before applying expensive regex operations. This reduces the dataset scanned and dramatically improves query performance. In the PSAA, a query that times out is as useless as a wrong query.

## KQL Foundations

KQL is a read-only, pipeline-based language. Data flows through operators separated by the pipe (`|`) character, with each stage refining the output 【turn0search1】【turn0search3】.

### Core Operators

| Operator | Purpose | PSAA Use Case |
|---|---|---|
| `where` | Filters rows by condition | Isolate failed login events, filter by IP or user |
| `project` | Selects specific columns | Keep only timestamp, account, and IP for reports |
| `take` | Limits output to N rows | Quick preview of unfamiliar tables |
| `order by` | Sorts results ascending/descending | Find latest or earliest events in a timeline |
| `summarize` | Groups and aggregates data | Count events by user, IP, or time bin |
| `join` | Merges rows from two tables on a common field | Correlate sign-in logs with threat intelligence feeds |
| `extend` | Creates a new calculated column | Add a parsed IP address or extracted timestamp |
| `parse` | Decomposes a string into structured columns | Break apart syslog messages or custom log formats |

### Time Filtering

Every investigation starts with a time scope. Use the `ago()` function to narrow the window:

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
```

This limits results to the last 24 hours, reducing noise before applying more specific filters.

## Regular Expressions for Log Analysis

Regex is essential when simple string matching (`has`, `contains`) falls short - for instance, matching IP address patterns, email formats, or specific log entry structures 【turn0search5】. KQL uses the **RE2 regex engine**, which does not support backreferences.

### Essential Regex Syntax (RE2)

| Pattern | Meaning | Example |
|---|---|---|
| `.` | Any character except newline | `h.t` matches "hat", "hit", "hot" |
| `\d` | Digit (0-9) | `port=\d+` matches "port=8080" |
| `\w` | Word character (alphanumeric + underscore) | `user_\w+` matches "user_admin" |
| `\s` | Whitespace | Matches space in "error code" |
| `+` | One or more of the preceding | `\d+` matches "42", "1337" |
| `*` | Zero or more of the preceding | `.*` matches everything |
| `?` | Zero or one (optional) | `https?` matches "http" and "https" |
| `{n}` | Exactly n occurrences | `\d{3}-\d{3}-\d{4}` matches phone numbers |
| `^` | Start of string/line | `^Error` matches lines starting with "Error" |
| `$` | End of string/line | `\.exe$` matches strings ending in ".exe" |
| `\b` | Word boundary | `\badmin\b` matches "admin" not "administration" |
| `[]` | Character class | `[aeiou]` matches any vowel |
| `[^]` | Negated character class | `[^0-9]` matches any non-digit |
| `()` | Capture group for extraction | `(\d+\.\d+\.\d+\.\d+)` captures an IP |
| `|` | Alternation (OR) | `error\|warning\|critical` |

### Special Consideration for KQL

Regular expressions in KQL must be double-escaped. The regex `\d` becomes `"\\d"` in KQL. This is a common pitfall during the exam.

## Applying Regex in KQL

### `matches regex` - Filtering Rows by Pattern

Filters records based on a case-sensitive regex match:

```kusto
SigninLogs
| where IPAddress matches regex @"^185\.220\.\d{1,3}\.\d{1,3}$"
```

This matches IP addresses in the 185.220.x.x range (commonly associated with Tor exit nodes).

### `contains` / `!contains` - Simple Substring Matching

Before reaching for regex, consider `contains` for simple substring searches - it is faster:

```kusto
AppInsights
| where message contains "error"
| where message !contains "warning"
```

### `extract()` - Regex Capture Groups

Extracts specific portions of a matched string into new columns:

```kusto
SigninLogs
| extend IP = extract(@"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", 1, EventDescription)
| where isnotempty(IP)
| project TimeGenerated, IP, EventDescription
```

### `parse` Operator - Decomposing Structured Strings

The `parse` operator breaks strings into calculated columns using literal or regex patterns:

**Simple parse mode:**
```kusto
Syslog
| parse SyslogMessage with "Failed password for " User " from " IP " port " Port
```

**Regex parse mode:**
```kusto
Syslog
| parse kind=regex flags=i SyslogMessage with "Failed password for " User " from " IP " port " Port
```

## Practical PSAA Investigation Walkthrough

**Scenario:** A user reports their account may be compromised. Find suspicious sign-in activity from unusual locations within the last 6 hours.

**Step 1 - Scope the timeframe:**
```kusto
SigninLogs
| where TimeGenerated > ago(6h)
```

**Step 2 - Filter for failed and risky sign-ins:**
```kusto
| where ResultType != "0"
```

**Step 3 - Use regex to match known-bad IP ranges:**
```kusto
| where IPAddress matches regex @"^185\.220\.\d{1,3}\.\d{1,3}$"
```

**Step 4 - Extract geographic location:**
```kusto
| extend City = extract(@"City:([^,]+)", 1, Location)
| extend Country = extract(@"Country:([^,]+)", 1, Location)
```

**Step 5 - Aggregate to find patterns:**
```kusto
| summarize AttemptCount = count() by UserPrincipalName, City, Country
| order by AttemptCount desc
| project UserPrincipalName, AttemptCount, City, Country
```

📌 **Exam Tip:** In KQL, `matches regex` is case-sensitive. Use the `(?i)` flag inside the regex or the `i` flag in the `parse` operator for case-insensitive matching. Also remember that KQL uses the RE2 engine — backreferences are not supported, so patterns like `(\\w+)\\s+\\1` will not work.

## Performance Optimization

| Practice | Why It Matters |
|---|---|
| Prefer `has` over `contains` | `has` searches for whole terms using indexed search, much faster |
| Filter by time first | Limiting the dataset before applying regex reduces scanned rows |
| Avoid regex when simpler operators suffice | `contains`, `has`, `startswith` are faster than `matches regex` |
| Test with `take` before full runs | Validate regex on 10 rows before scanning millions |

<details>
<summary>Common Mistakes to Avoid</summary>

- **Forgetting double-escaping:** Write `\\d` not `\d` in KQL regex strings.
- **Not testing with `take`:** Always verify regex on a sample before full execution.
- **Case sensitivity:** `matches regex` is case-sensitive; use `(?i)` or the `i` flag in `parse` for case-insensitive matching.
- **Maximum 16 regex groups:** Complex patterns with more capture groups will fail.
</details>

```mermaid
flowchart TD
    Q[Investigation Question] --> T{Time Scope}
    T -->|Last 24h| TW[where TimeGenerated > ago(24h)]
    T -->|Custom range| TW2[where TimeGenerated between (start..end)]
    
    TW --> F{Filter Method?}
    TW2 --> F
    F -->|Simple string| S[contains / has / startswith]
    F -->|Complex pattern| R[matches regex]
    
    S --> E{Extract data?}
    R --> E
    E -->|Yes| EXT[extract with capture groups / parse operator]
    E -->|No| AGG[summarize / project / order by]
    EXT --> AGG
    AGG --> Result[Evidence for Report]
```

## Quick Reference Card

| Task | KQL Operator | Example |
|---|---|---|
| Simple substring search | `where Column contains "text"` | `contains "failed"` |
| Whole-term search (fast) | `where Column has "term"` | `has "error"` |
| Regex pattern match | `where Column matches regex "pat"` | `matches regex "\\d{3}-\\d{2}-\\d{4}"` |
| Extract with regex group | `extend Col = extract("(pat)", 1, Col)` | `extract("IP:([0-9.]+)", 1, Log)` |
| Structured parsing | `parse Column with ...` | `parse Syslog with "from " IP` |
| Time filtering | `where TimeGenerated > ago(nh)` | `where TimeGenerated > ago(24h)` |
| Aggregation | `summarize count() by Column` | `summarize count() by Account` |
| Sorting | `order by Column desc` | `order by TimeGenerated desc` |

```mermaid
flowchart TD
    Q[Start: Investigation Question] --> T{Table Selection}
    T -->|SigninLogs| S1[Filter by Time: ago()]
    T -->|SecurityEvent| S1
    T -->|CommonSecurityLog| S1
    S1 --> F{Pattern Type?}
    F -->|Simple string| H[has / contains]
    F -->|Regex pattern| R[matches regex]
    H --> E[Extract fields]
    R --> D[Double-escape \\d]
    D --> E
    E --> A[Aggregate with summarize]
    A --> O[Order and output]
    O --> V[Validate evidence]
    V --> R2[Report finding]
```

## Recap

KQL and regex are the primary tools for searching and filtering log data in Microsoft Sentinel. KQL's pipeline architecture (where, project, summarize, join) enables efficient data reduction and aggregation. Regex provides pattern matching for complex log entries when simple string operators are insufficient. Together, they allow rapid isolation of malicious activity across massive datasets. Double-escaped strings, time-first filtering, and testing with `take` are essential practices for efficient investigation.
