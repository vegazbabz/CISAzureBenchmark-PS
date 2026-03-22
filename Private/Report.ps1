# HTML report generator — self-contained single-file output
# Matches the layout and style of the Python CIS Azure Audit Tool report.
Add-Type -AssemblyName System.Web

function New-CISHtmlReport {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Factory function that constructs and returns an object; does not modify system state.')]
    param(
        [Parameter(Mandatory)][object[]]$Results,
        [Parameter(Mandatory)][string]$OutputPath,
        [string]$ScopeLabel       = "",
        [object[]]$History        = @(),
        [hashtable]$ScopeInfo     = @{},
        [hashtable]$SubTimestamps = @{}
    )

    # ── Status styles: bg, text color, HTML entity icon ──────────────────────
    $sStyle = @{
        'PASS'       = @{ Bg='#f0fdf4'; Col='#16a34a'; Icon='&#x2705;' }
        'FAIL'       = @{ Bg='#fef2f2'; Col='#dc2626'; Icon='&#x274C;' }
        'ERROR'      = @{ Bg='#fff7ed'; Col='#ea580c'; Icon='&#x26A0;&#xFE0F;' }
        'INFO'       = @{ Bg='#eff6ff'; Col='#2563eb'; Icon='&#x2139;&#xFE0F;' }
        'MANUAL'     = @{ Bg='#f5f3ff'; Col='#7c3aed'; Icon='&#x1F4CB;' }
        'SUPPRESSED' = @{ Bg='#f1f5f9'; Col='#64748b'; Icon='&#x1F507;' }
    }

    # ── Counts & score ────────────────────────────────────────────────────────
    $counts = @{ PASS=0; FAIL=0; ERROR=0; INFO=0; MANUAL=0; SUPPRESSED=0 }
    foreach ($r in $Results) { if ($counts.ContainsKey($r.Status)) { $counts[$r.Status]++ } }
    $overallTotal = $counts.PASS + $counts.FAIL + $counts.ERROR
    $score     = if ($overallTotal -gt 0) { [math]::Round(100.0 * $counts.PASS / $overallTotal, 1) } else { 0 }
    $scoreCol  = if ($score -ge 80) { '#16a34a' } elseif ($score -ge 60) { '#d97706' } else { '#dc2626' }

    # ── L1 / L2 breakdown ─────────────────────────────────────────────────────
    $l1 = @{ PASS=0; FAIL=0; ERROR=0 }
    $l2 = @{ PASS=0; FAIL=0; ERROR=0 }
    foreach ($r in $Results) {
        $s = $r.Status
        if ($r.Level -eq 1 -and $l1.ContainsKey($s)) { $l1[$s]++ }
        if ($r.Level -eq 2 -and $l2.ContainsKey($s)) { $l2[$s]++ }
    }
    $l1Total  = $l1.PASS + $l1.FAIL + $l1.ERROR
    $l2Total  = $l2.PASS + $l2.FAIL + $l2.ERROR
    $l1Score  = if ($l1Total -gt 0) { [math]::Round(100.0 * $l1.PASS / $l1Total, 1) } else { 0 }
    $l2Score  = if ($l2Total -gt 0) { [math]::Round(100.0 * $l2.PASS / $l2Total, 1) } else { 0 }
    $l1Col    = if ($l1Score -ge 80) { '#16a34a' } elseif ($l1Score -ge 60) { '#d97706' } else { '#dc2626' }
    $l2Col    = if ($l2Score -ge 80) { '#16a34a' } elseif ($l2Score -ge 60) { '#d97706' } else { '#dc2626' }

    # ── Group results by section ──────────────────────────────────────────────
    $sectionMap = @{}
    foreach ($r in $Results) {
        $sec = $r.Section
        if (-not $sectionMap.ContainsKey($sec)) { $sectionMap[$sec] = [System.Collections.Generic.List[object]]::new() }
        $sectionMap[$sec].Add($r)
    }

    # ── Per-section data for JS charts ────────────────────────────────────────
    $secData = @{}
    foreach ($sec in $sectionMap.Keys) {
        $grp = $sectionMap[$sec]
        $sp  = @($grp | Where-Object { $_.Status -eq 'PASS'  }).Count
        $sf  = @($grp | Where-Object { $_.Status -eq 'FAIL'  }).Count
        $se  = @($grp | Where-Object { $_.Status -eq 'ERROR' }).Count
        $ss  = if (($sp+$sf+$se) -gt 0) { [math]::Round(100.0*$sp/($sp+$sf+$se),1) } else { 0 }
        $secData[$sec] = [ordered]@{ pass=$sp; fail=$sf; error=$se; score=$ss }
    }
    $secDataJson = $secData | ConvertTo-Json -Compress -Depth 3

    # ── Build table rows ──────────────────────────────────────────────────────
    $rows  = [System.Text.StringBuilder]::new()
    $secIdx = 0
    $sortedSecs = @($sectionMap.Keys | Sort-Object { Get-ControlSortKey ($_ -split ' ' | Select-Object -First 1) })

    foreach ($sec in $sortedSecs) {
        $secId   = "sec-$secIdx"; $secIdx++
        $grp     = @($sectionMap[$sec])
        $sp      = @($grp | Where-Object { $_.Status -eq 'PASS' }).Count
        $secH    = [System.Web.HttpUtility]::HtmlEncode($sec)

        [void]$rows.Append(
            "<tr class=`"sh`" data-sec-id=`"$secId`">" +
            "<td colspan=`"6`">" +
            "<span class=`"sec-arrow open`">&#x25BC;</span>" +
            "<b>$secH</b>" +
            "<span class=`"ss`">$sp of $($grp.Count) checks passed</span>" +
            "</td></tr>`n")

        $sortedGrp = @($grp | Sort-Object { Get-ControlSortKey $_.ControlId }, { $_.SubscriptionName }, { $_.Resource })

        foreach ($r in $sortedGrp) {
            $st = if ($sStyle.ContainsKey($r.Status)) { $sStyle[$r.Status] } else { @{ Bg='#f9fafb'; Col='#374151'; Icon='?' } }

            $subCell = if ($r.SubscriptionName) {
                "<div class=`"sub-name`">&#x1F4CB; $([System.Web.HttpUtility]::HtmlEncode($r.SubscriptionName))</div>"
            } else {
                "<div class=`"sub-name`" style=`"color:#94a3b8`">Tenant-wide</div>"
            }
            if ($r.Resource) {
                $subCell += "<div class=`"res-name`">&#x1F539; <code>$([System.Web.HttpUtility]::HtmlEncode($r.Resource))</code></div>"
            }

            $fix = ''
            if ($r.Remediation -and $r.Status -eq 'FAIL') {
                $fix = "<div class=`"fix`">&#x1F4A1; $([System.Web.HttpUtility]::HtmlEncode($r.Remediation))</div>"
            }

            [void]$rows.Append(
                "<tr style=`"background:$($st.Bg)`" " +
                "data-sec=`"$secId`" " +
                "data-sec-name=`"$([System.Web.HttpUtility]::HtmlEncode($sec))`" " +
                "data-status=`"$($r.Status)`" " +
                "data-level=`"L$($r.Level)`" " +
                "data-sub=`"$([System.Web.HttpUtility]::HtmlEncode($r.SubscriptionName))`">" +
                "<td><code>$([System.Web.HttpUtility]::HtmlEncode($r.ControlId))</code></td>" +
                "<td><span class=`"lv`">L$($r.Level)</span></td>" +
                "<td>$([System.Web.HttpUtility]::HtmlEncode($r.Title))</td>" +
                "<td class=`"sub-col`">$subCell</td>" +
                "<td><span class=`"badge`" style=`"color:$($st.Col)`">$($st.Icon) $($r.Status)</span></td>" +
                "<td>$([System.Web.HttpUtility]::HtmlEncode($r.Details))$fix</td>" +
                "</tr>`n")
        }
    }

    # ── Subscription summary ──────────────────────────────────────────────────
    $subStats = @{}
    foreach ($r in $Results) {
        $sn = $r.SubscriptionName
        if (-not $sn) { continue }
        if (-not $subStats.ContainsKey($sn)) { $subStats[$sn] = @{ PASS=0; FAIL=0; ERROR=0; INFO=0; MANUAL=0; SUPPRESSED=0 } }
        if ($subStats[$sn].ContainsKey($r.Status)) { $subStats[$sn][$r.Status]++ }
    }

    $subRowsHtml = [System.Text.StringBuilder]::new()
    $sortedSubs  = @($subStats.Keys | Sort-Object {
        $s = $subStats[$_]; $d = $s.PASS+$s.FAIL+$s.ERROR
        if ($d -gt 0) { $s.PASS / $d * 100 } else { 0 }
    })
    foreach ($sn in $sortedSubs) {
        $st     = $subStats[$sn]
        $scored = [math]::Max($st.PASS+$st.FAIL+$st.ERROR, 1)
        $pct    = [math]::Round($st.PASS / $scored * 100, 1)
        $col    = if ($pct -ge 80) { '#16a34a' } elseif ($pct -ge 60) { '#d97706' } else { '#dc2626' }
        $passW  = [math]::Round($st.PASS / $scored * 100)
        $failW  = [math]::Round($st.FAIL / $scored * 100)
        $errW   = [math]::Max(0, 100-$passW-$failW)
        $bar    = "<div class=`"sbar`">" +
                  "<span style=`"width:$passW%;background:#16a34a`"></span>" +
                  "<span style=`"width:$failW%;background:#dc2626`"></span>" +
                  "<span style=`"width:$errW%;background:#ea580c`"></span></div>"
        $snH         = [System.Web.HttpUtility]::HtmlEncode($sn)
        # Audited cell — show date and staleness relative to today
        $auditedCell = '<td>&#8212;</td>'
        if ($SubTimestamps.ContainsKey($sn)) {
            try {
                $aud    = ([DateTimeOffset]::Parse($SubTimestamps[$sn])).Date
                $today2 = [DateTimeOffset]::UtcNow.Date
                $age    = ($today2 - $aud).Days
                $aLbl   = if ($age -eq 0) { 'today' } elseif ($age -eq 1) { 'yesterday' } else { "${age}d ago" }
                $aCol   = if ($age -le 1) { '#64748b' } elseif ($age -le 30) { '#d97706' } else { '#dc2626' }
                $aDt    = $aud.ToString('MMM dd')
                $auditedCell = "<td style=`"color:$aCol;white-space:nowrap`">$aDt<br><small>$aLbl</small></td>"
            } catch { $null = $_ <# Graceful: if date parsing fails, omit the 'last audited' cell #> }
        }
        [void]$subRowsHtml.Append(
            "<tr class=`"sub-row`" data-sub=`"$snH`">" +
            "<td style=`"font-weight:600`">$snH</td>" +
            "<td><span style=`"color:$col;font-weight:700`">$pct%</span></td>" +
            "<td>$bar</td>" +
            "<td style=`"color:#16a34a;font-weight:600`">$($st.PASS)</td>" +
            "<td style=`"color:#dc2626;font-weight:600`">$($st.FAIL)</td>" +
            "<td style=`"color:#ea580c`">$($st.ERROR)</td>" +
            "<td style=`"color:#64748b`">$($st.INFO)</td>" +
            "<td style=`"color:#7c3aed`">$($st.MANUAL)</td>" +
            "<td style=`"color:#64748b`">$($st.SUPPRESSED)</td>" +
            $auditedCell +
            "</tr>`n")
    }

    $subTable = ''
    if ($subRowsHtml.Length -gt 0) {
        $subTable = @"
<div class="sub-summary-wrap">
<h2 id="sub-summary-toggle" style="cursor:pointer;user-select:none"><span class="sec-arrow open" id="sub-summary-arrow">&#x25BC;</span> Subscription Summary <small>(click a row to filter the table below)</small></h2>
<div id="sub-summary-body">
<table class="sub-summary"><thead><tr>
<th>Subscription</th><th>Score</th><th>Breakdown</th>
<th>&#10003; Pass</th><th>&#10007; Fail</th><th>&#9888; Error</th>
<th>Info</th><th>Manual</th><th>&#128263; Suppressed</th>
<th>Audited</th>
</tr></thead><tbody>$($subRowsHtml.ToString())</tbody></table>
</div></div>
"@
    }

    # ── Scope info block ──────────────────────────────────────────────────────
    $scopeBlock = ''
    $scopeRows  = [System.Text.StringBuilder]::new()
    if ($ScopeInfo.tenant) {
        [void]$scopeRows.Append("<tr><th>Tenant</th><td>$([System.Web.HttpUtility]::HtmlEncode([string]$ScopeInfo.tenant))</td></tr>`n")
    }
    if ($ScopeInfo.user) {
        $callerLabel = if ([string]$ScopeInfo.caller_type -eq 'servicePrincipal') { 'service principal' } else { 'user' }
        [void]$scopeRows.Append("<tr><th>Audited by</th><td>$([System.Web.HttpUtility]::HtmlEncode([string]$ScopeInfo.user)) <span style=`"color:#94a3b8;font-size:0.85em`">($callerLabel)</span></td></tr>`n")
    }
    # Scope row — always shown (mirrors Python scope_label)
    $sl = if ($ScopeInfo.scope_label) { [string]$ScopeInfo.scope_label } elseif ($ScopeLabel) { $ScopeLabel } else { $null }
    if ($sl) {
        [void]$scopeRows.Append("<tr><th>Scope</th><td>$([System.Web.HttpUtility]::HtmlEncode($sl))</td></tr>`n")
    }
    # Subscriptions row — shown when the list is available
    if ($ScopeInfo.subscriptions -and @($ScopeInfo.subscriptions).Count -gt 0) {
        $siSubs   = @($ScopeInfo.subscriptions)
        $subsHtml = ($siSubs | ForEach-Object { [System.Web.HttpUtility]::HtmlEncode([string]$_) }) -join ', '
        [void]$scopeRows.Append("<tr><th>Subscriptions ($($siSubs.Count))</th><td>$subsHtml</td></tr>`n")
    }
    if ($ScopeInfo.level_filter -and [string]$ScopeInfo.level_filter -ne 'both') {
        [void]$scopeRows.Append("<tr><th>Level filter</th><td>Level $([System.Web.HttpUtility]::HtmlEncode([string]$ScopeInfo.level_filter)) only</td></tr>`n")
    }
    if ($scopeRows.Length -gt 0) {
        $scopeBlock = "<div class=`"scope-info`"><table>$($scopeRows.ToString())</table></div>"
    }

    # ── Trend chart ───────────────────────────────────────────────────────────
    $trendBlock = ''
    if (@($History).Count -ge 2) {
        $fh = @($History | Where-Object { $_.score -gt 0 }) | Select-Object -Last 30
        if ($fh.Count -ge 2) {
            $trendJson = ($fh | ForEach-Object {
                $ts2 = if ($_.timestamp) { [string]$_.timestamp -replace 'T.*','' } else { '' }
                [PSCustomObject]@{ ts=$ts2; score=$_.score }
            } | ConvertTo-Json -Compress)
            $trendBlock = @"
<details class="trend-box">
  <summary>&#128200; Compliance Trend &#8212; last $($fh.Count) run(s)</summary>
  <div class="trend-inner"><canvas id="trend-cv" height="130"></canvas></div>
</details>
<script>
(function(){
  var TREND = $trendJson;
  var cv = document.getElementById('trend-cv');
  if (!cv || !TREND.length) return;
  cv.width = cv.parentElement.offsetWidth || 700;
  var W=cv.width, H=cv.height, PAD={t:20,r:20,b:36,l:44};
  var iW=W-PAD.l-PAD.r, iH=H-PAD.t-PAD.b;
  var ctx=cv.getContext('2d');
  var scores=TREND.map(function(d){return d.score;});
  var minS=Math.max(0,Math.min.apply(null,scores)-5);
  var maxS=Math.min(100,Math.max.apply(null,scores)+5);
  function sx(i){return PAD.l+(i/(TREND.length-1))*iW;}
  function sy(v){return PAD.t+iH-((v-minS)/(maxS-minS))*iH;}
  ctx.strokeStyle='#e2e8f0'; ctx.lineWidth=1;
  [0,25,50,75,100].forEach(function(v){
    if(v<minS||v>maxS)return;
    var y=sy(v); ctx.beginPath(); ctx.moveTo(PAD.l,y); ctx.lineTo(PAD.l+iW,y); ctx.stroke();
    ctx.fillStyle='#94a3b8'; ctx.font='11px sans-serif'; ctx.textAlign='right';
    ctx.fillText(v+'%',PAD.l-6,y+4);
  });
  ctx.beginPath(); ctx.moveTo(sx(0),sy(scores[0]));
  scores.forEach(function(s,i){if(i)ctx.lineTo(sx(i),sy(s));});
  ctx.lineTo(sx(scores.length-1),PAD.t+iH); ctx.lineTo(sx(0),PAD.t+iH); ctx.closePath();
  ctx.fillStyle='rgba(37,99,235,0.08)'; ctx.fill();
  ctx.beginPath(); scores.forEach(function(s,i){i?ctx.lineTo(sx(i),sy(s)):ctx.moveTo(sx(i),sy(s));});
  ctx.strokeStyle='#2563eb'; ctx.lineWidth=2; ctx.stroke();
  TREND.forEach(function(d,i){
    var x=sx(i),y=sy(d.score);
    var col=d.score>=80?'#16a34a':d.score>=60?'#d97706':'#dc2626';
    ctx.beginPath(); ctx.arc(x,y,4,0,2*Math.PI); ctx.fillStyle=col; ctx.fill();
    ctx.strokeStyle='#fff'; ctx.lineWidth=1.5; ctx.stroke();
    ctx.fillStyle=col; ctx.font='bold 11px sans-serif'; ctx.textAlign='center';
    ctx.fillText(d.score+'%',x,y-9);
    ctx.fillStyle='#64748b'; ctx.font='10px sans-serif'; ctx.fillText(d.ts,x,H-8);
  });
})();
</script>
"@
        }
    }

    # ── JS data ───────────────────────────────────────────────────────────────
    $jsCountsJson = [PSCustomObject]@{ PASS=$counts.PASS; FAIL=$counts.FAIL; ERROR=$counts.ERROR } | ConvertTo-Json -Compress
    $jsL1Json     = [PSCustomObject]@{ pass=$l1.PASS; fail=$l1.FAIL; error=$l1.ERROR } | ConvertTo-Json -Compress
    $jsL2Json     = [PSCustomObject]@{ pass=$l2.PASS; fail=$l2.FAIL; error=$l2.ERROR } | ConvertTo-Json -Compress

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm UTC"

    # ── Assemble HTML ─────────────────────────────────────────────────────────
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CIS Azure Audit Report &#8212; $ts</title>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       background: #f8fafc; color: #1e293b; line-height: 1.5; }

header { background: linear-gradient(135deg, #1e3a5f 0%, #2563eb 100%);
         color: #fff; padding: 2rem; }
header h1 { font-size: 1.6rem; font-weight: 700; margin-bottom: .25rem; }
header p  { opacity: .8; font-size: .9rem; }

.cards { display: flex; gap: 1rem; padding: 1.5rem 2rem; flex-wrap: wrap; }
.card  { flex: 1; min-width: 120px; background: #fff; border-radius: 10px;
         padding: 1.2rem; text-align: center; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
.card .n { font-size: 2rem; font-weight: 800; line-height: 1; }
.card .l { font-size: .78rem; color: #64748b; margin-top: .3rem; }
.c-sc .n { font-size: 2.4rem; }
.c-pa .n { color: #16a34a; }
.c-fa .n { color: #dc2626; }
.c-er .n { color: #ea580c; }
.c-in .n { color: #2563eb; }
.c-ma .n { color: #7c3aed; }
.c-su .n { color: #64748b; }

.trend-box { margin: 0 2rem 1rem; border: 1px solid #e2e8f0; border-radius: 8px;
    background: #fff; overflow: hidden; }
.trend-box > summary { padding: .65rem 1rem; font-size: .85rem; font-weight: 600;
    color: #475569; cursor: pointer; list-style: none; user-select: none; }
.trend-box > summary::-webkit-details-marker { display: none; }
.trend-box > summary:hover { background: #f8fafc; }
.trend-inner { padding: .75rem 1rem 1rem; }
.trend-inner canvas { width: 100%; display: block; }

.filters { display: flex; align-items: center; gap: .75rem; padding: .8rem 2rem;
           background: #fff; border-bottom: 1px solid #e2e8f0; flex-wrap: wrap; }
.filters label { font-weight: 600; font-size: .85rem; color: #475569; }
.filters input, .filters select { border: 1px solid #cbd5e1; border-radius: 6px;
    padding: .4rem .7rem; font-size: .85rem; outline: none; }
.filters input { min-width: 220px; }
.filters input:focus { border-color: #2563eb; }
.exp-btn { background: #1e3a5f; color: #fff; border-radius: 6px; padding: .4rem .8rem;
    font-size: .85rem; text-decoration: none; white-space: nowrap;
    border: none; cursor: pointer; font-family: inherit; }
.exp-btn:hover { background: #2563eb; }

.wrap  { overflow-x: auto; padding: 0 2rem 2rem; }
table  { width: 100%; border-collapse: collapse; font-size: .84rem;
         background: #fff; border-radius: 10px; overflow: hidden;
         box-shadow: 0 1px 4px rgba(0,0,0,.08); }
thead  { background: #1e3a5f; color: #fff; }
th, td { padding: .55rem .8rem; text-align: left; border-bottom: 1px solid #e2e8f0; }
th     { font-size: .78rem; text-transform: uppercase; letter-spacing: .04em; }

tr.sh td { background: #f1f5f9; font-size: .8rem; color: #475569;
           border-top: 2px solid #cbd5e1; padding: .5rem .8rem; }
tr.sh  { cursor: pointer; user-select: none; }
tr.sh:hover td { background: #e2e8f0; }
.sec-arrow { display: inline-block; margin-right: .45rem; font-size: .8rem;
             transition: transform .2s ease; }
.sec-arrow.open   { transform: rotate(0deg); }
.sec-arrow.closed { transform: rotate(-90deg); }
.row-hidden { display: none !important; }
.ss { float: right; color: #94a3b8; font-weight: normal; }

.badge { font-size: .78rem; font-weight: 700; white-space: nowrap; }
.lv    { font-size: .7rem; background: #e2e8f0; border-radius: 4px;
         padding: 1px 5px; font-weight: 600; color: #475569; }

.sub-col  { min-width: 180px; max-width: 240px; vertical-align: top; }
.sub-name { font-size: .78rem; color: #374151; font-weight: 600; padding: 1px 0; margin-bottom: 2px; }
.res-name { font-size: .76rem; color: #6b7280; margin-top: 3px; }
.res-name code { background: rgba(0,0,0,.06); padding: 1px 4px; border-radius: 3px; }

.fix { margin-top: .4rem; font-size: .78rem; color: #64748b; font-style: italic; }

.scope-info { margin-top: 1rem; }
.scope-info table { border-collapse: collapse; font-size: .82rem;
    background: rgba(255,255,255,.12); border-radius: 6px; overflow: hidden; }
.scope-info th { color: rgba(255,255,255,.7); font-weight: 600; padding: .25rem .8rem;
    text-align: right; white-space: nowrap; border-right: 1px solid rgba(255,255,255,.2); }
.scope-info td { color: #fff; padding: .25rem .8rem; }

footer { text-align: center; padding: 1.5rem; color: #94a3b8; font-size: .8rem; }

.sub-summary-wrap { padding: 0 2rem 1.5rem; }
.sub-summary-wrap h2 { font-size: 1rem; font-weight: 700; color: #1e293b; margin-bottom: .6rem; }
.sub-summary-wrap h2 small { font-size: .75rem; color: #94a3b8; font-weight: normal; }
.sub-summary { width: 100%; border-collapse: collapse; background: #fff;
    border-radius: 10px; overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
.sub-summary thead { background: #1e3a5f; color: #fff; }
.sub-summary th, .sub-summary td { padding: .45rem .8rem; text-align: left;
    border-bottom: 1px solid #e2e8f0; font-size: .83rem; }
.sub-summary th { font-size: .75rem; text-transform: uppercase; letter-spacing: .04em; }
.sub-row { cursor: pointer; }
.sub-row:hover { background: #f1f5f9 !important; }
.sub-row.active { background: #dbeafe !important; outline: 2px solid #2563eb; }
.sbar { display: flex; height: 8px; border-radius: 4px; overflow: hidden;
    min-width: 120px; background: #e2e8f0; }
.sbar span { display: block; height: 100%; }

#back-top { position: fixed; bottom: 1.5rem; right: 1.5rem; width: 2.5rem; height: 2.5rem;
    background: #2563eb; color: #fff; border-radius: 50%; font-size: 1.1rem;
    box-shadow: 0 2px 8px rgba(0,0,0,.2); text-decoration: none;
    display: flex; align-items: center; justify-content: center; z-index: 999; }
#back-top:hover { background: #1d4ed8; }

.dashboard { display: flex; gap: 2rem; padding: 1rem 2rem 1.5rem;
    flex-wrap: wrap; align-items: flex-start; background: #fff;
    border-bottom: 1px solid #e2e8f0; }
.dash-donuts { display: flex; gap: 2rem; flex-wrap: wrap; align-items: flex-start; }
.donut-group { display: flex; flex-direction: column; align-items: center; gap: .25rem; }
.donut-label { font-size: .7rem; font-weight: 700; color: #475569;
    text-transform: uppercase; letter-spacing: .05em; text-align: center; margin-bottom: .15rem; }
.lv-badge { font-size: .62rem; font-weight: 700; color: #fff; border-radius: 3px;
    padding: 0 4px; margin-left: 4px; vertical-align: middle; }
.donut-pct { font-size: 1.45rem; font-weight: 800; line-height: 1; margin-top: .2rem; }
.donut-cnt { font-size: .72rem; color: #94a3b8; margin-top: .1rem; }
.donut-legend { display: flex; gap: .9rem; margin-top: .7rem; flex-wrap: wrap; }
.donut-legend span { display: flex; align-items: center; gap: .35rem;
    font-size: .74rem; color: #475569; }
.donut-legend i { display: inline-block; width: 10px; height: 10px; border-radius: 2px; }
.sec-breakdown { flex: 1; min-width: 260px; }
.sb-title { font-size: .72rem; font-weight: 700; color: #475569;
    text-transform: uppercase; letter-spacing: .05em; margin-bottom: .75rem; }
.sb-subtitle { font-size: .67rem; font-weight: 400; color: #94a3b8;
    text-transform: none; letter-spacing: 0; margin-left: .4rem; }
.sb-row { display: flex; align-items: center; gap: .6rem; margin-bottom: .42rem; }
.sb-name { font-size: .77rem; color: #1e293b; font-weight: 500; width: 200px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex-shrink: 0; }
.sb-bar { flex: 1; height: 9px; border-radius: 5px; background: #e2e8f0;
    overflow: hidden; display: flex; min-width: 80px; }
.sb-bar span { display: block; height: 100%; }
.sb-pct { font-size: .77rem; font-weight: 700; width: 40px; text-align: right; flex-shrink: 0; }

@media print {
    #back-top, .filters, .trend-box { display: none !important; }
    .sec-arrow { display: none; }
    body { background: #fff; font-size: .78rem; }
    .wrap { overflow: visible; padding: 0 1rem 1rem; }
    header, tr[style], tr.sh td, thead, .cards .card { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .cards .card { box-shadow: none; border: 1px solid #e2e8f0; }
    table, .sub-summary { box-shadow: none; }
    thead { display: table-header-group; }
    tr { page-break-inside: avoid; }
    tr.sh { page-break-inside: avoid; page-break-after: avoid; cursor: default; }
    .dashboard { page-break-inside: avoid; }
    .sub-summary-wrap { page-break-inside: avoid; }
    .sub-summary-wrap h2 small { display: none; }
    .sub-col { min-width: 100px; max-width: 160px; }
    table { font-size: .78rem; }
    .sub-row:hover { background: inherit !important; }
    .sub-row.active { outline: none; background: inherit !important; }
}
</style>
</head>
<body>
<a id="top"></a>
<header>
  <h1>&#x1F512; CIS Azure Audit Report &#8212; $ts</h1>
  <p>Audit Tool v$($script:CIS_VERSION) &nbsp;&middot;&nbsp; CIS Microsoft Azure Foundations Benchmark v$($script:BENCHMARK_VER)</p>
  $scopeBlock
</header>

<div class="cards">
  <div class="card c-sc"><div class="n" style="color:$scoreCol">$score%</div><div class="l">Compliance Score</div></div>
  <div class="card c-pa"><div class="n">$($counts.PASS)</div><div class="l">&#x2705; Passed</div></div>
  <div class="card c-fa"><div class="n">$($counts.FAIL)</div><div class="l">&#x274C; Failed</div></div>
  <div class="card c-er"><div class="n">$($counts.ERROR)</div><div class="l">&#x26A0;&#xFE0F; Errors</div></div>
  <div class="card c-in"><div class="n">$($counts.INFO)</div><div class="l">&#x2139;&#xFE0F; Info/N/A</div></div>
  <div class="card c-ma"><div class="n">$($counts.MANUAL)</div><div class="l">&#x1F4CB; Manual</div></div>
  <div class="card c-su"><div class="n">$($counts.SUPPRESSED)</div><div class="l">&#x1F507; Suppressed</div></div>
</div>

<div class="dashboard">
  <div class="dash-donuts">
    <div class="donut-group">
      <div class="donut-label">Overall</div>
      <canvas id="d-overall" width="110" height="110"></canvas>
      <div id="pct-overall" class="donut-pct" style="color:$scoreCol">$score%</div>
      <div id="cnt-overall" class="donut-cnt">$($counts.PASS) / $overallTotal pass</div>
    </div>
    <div class="donut-group">
      <div class="donut-label">Level 1<span class="lv-badge" style="background:#dc2626">L1</span></div>
      <canvas id="d-l1" width="110" height="110"></canvas>
      <div id="pct-l1" class="donut-pct" style="color:$l1Col">$l1Score%</div>
      <div id="cnt-l1" class="donut-cnt">$($l1.PASS) / $l1Total pass</div>
    </div>
    <div class="donut-group">
      <div class="donut-label">Level 2<span class="lv-badge" style="background:#7c3aed">L2</span></div>
      <canvas id="d-l2" width="110" height="110"></canvas>
      <div id="pct-l2" class="donut-pct" style="color:$l2Col">$l2Score%</div>
      <div id="cnt-l2" class="donut-cnt">$($l2.PASS) / $l2Total pass</div>
    </div>
    <div class="donut-legend">
      <span><i style="background:#16a34a"></i>Pass</span>
      <span><i style="background:#dc2626"></i>Fail</span>
      <span><i style="background:#cbd5e1"></i>Error / N/A</span>
    </div>
  </div>
  <div class="sec-breakdown" id="sec-breakdown"></div>
</div>

$trendBlock
$subTable

<div class="filters">
  <label>Filter:</label>
  <input id="s" placeholder="Search control ID or title...">
  <select id="st">
    <option value="">All statuses</option>
    <option>PASS</option><option>FAIL</option><option>ERROR</option>
    <option>INFO</option><option>MANUAL</option><option>SUPPRESSED</option>
  </select>
  <select id="lv">
    <option value="">All levels</option>
    <option value="L1">Level 1</option><option value="L2">Level 2</option>
  </select>
  <button class="exp-btn" onclick="exportCsv()">&#8681; Export CSV</button>
  <button class="exp-btn" onclick="exportJson()">&#8681; Export JSON</button>
</div>

<div class="wrap"><table>
<thead><tr>
  <th>Control</th><th>Level</th><th>Title</th><th>Subscription / Resource</th><th>Status</th><th>Details</th>
</tr></thead>
<tbody id="tb">$($rows.ToString())</tbody>
</table></div>

<a href="#top" id="back-top" title="Back to top">&#8679;</a>
<footer>
  CIS Microsoft Azure Foundations Benchmark v$($script:BENCHMARK_VER) &nbsp;&middot;&nbsp;
  Tool v$($script:CIS_VERSION) &nbsp;&middot;&nbsp;
  Compliance score excludes INFO, MANUAL and SUPPRESSED checks.
  Manual controls require separate review per the CIS benchmark document.
</footer>

<script>
(function(){
  var s  = document.getElementById('s');
  var st = document.getElementById('st');
  var lv = document.getElementById('lv');

  var JS_COUNTS   = $jsCountsJson;
  var JS_L1       = $jsL1Json;
  var JS_L2       = $jsL2Json;
  var JS_SECTIONS = $secDataJson;
  var subF = '';
  var _collapsed = {};

  // Subscription summary collapse/expand toggle
  var subToggle = document.getElementById('sub-summary-toggle');
  var subBody   = document.getElementById('sub-summary-body');
  var subArrow  = document.getElementById('sub-summary-arrow');
  if (subToggle && subBody) {
    subToggle.addEventListener('click', function(){
      var hidden = subBody.style.display === 'none';
      subBody.style.display = hidden ? '' : 'none';
      if (subArrow) { subArrow.classList.toggle('closed', !hidden); subArrow.classList.toggle('open', hidden); }
    });
  }

  document.querySelectorAll('#tb tr.sh').forEach(function(hdr){
    hdr.addEventListener('click', function(){
      var id = hdr.dataset.secId;
      _collapsed[id] = !_collapsed[id];
      var arrow = hdr.querySelector('.sec-arrow');
      arrow.classList.toggle('closed', _collapsed[id]);
      arrow.classList.toggle('open', !_collapsed[id]);
      filter();
    });
  });

  function filter(){
    var sv  = s.value.toLowerCase();
    var stv = st.value;
    var lvv = lv.value;
    var filtering = !!(sv || stv || lvv || subF);

    document.querySelectorAll('#tb tr:not(.sh)').forEach(function(r){
      var badge = r.querySelector('.badge');
      var lb    = r.querySelector('.lv');
      var ok = (!sv  || r.textContent.toLowerCase().includes(sv))
              && (!stv || (badge && badge.textContent.includes(stv)))
              && (!lvv || (lb    && lb.textContent === lvv))
              && (!subF || r.dataset.sub === subF);
      r.dataset.filterMatch = ok ? '1' : '0';
      r.classList.toggle('row-hidden', !(ok && (!_collapsed[r.dataset.sec] || filtering)));
    });

    document.querySelectorAll('#tb tr.sh').forEach(function(h){
      var sib = h.nextElementSibling;
      var anyMatch = false;
      while (sib && !sib.classList.contains('sh')){
        if (sib.dataset.filterMatch === '1') anyMatch = true;
        sib = sib.nextElementSibling;
      }
      h.classList.toggle('row-hidden', !anyMatch);
    });
  }

  s.addEventListener('input', filter);
  st.addEventListener('change', filter);
  lv.addEventListener('change', filter);

  document.querySelectorAll('.sub-row').forEach(function(row){
    row.addEventListener('click', function(){
      if (subF === row.dataset.sub){
        subF = '';
        row.classList.remove('active');
      } else {
        subF = row.dataset.sub;
        document.querySelectorAll('.sub-row').forEach(function(r){ r.classList.remove('active'); });
        row.classList.add('active');
      }
      filter();
      updateCharts();
    });
  });

  function updateCharts(){
    var counts, l1, l2, secs;
    if (!subF){
      counts = JS_COUNTS; l1 = JS_L1; l2 = JS_L2; secs = JS_SECTIONS;
    } else {
      counts = {PASS:0,FAIL:0,ERROR:0};
      l1 = {pass:0,fail:0,error:0};
      l2 = {pass:0,fail:0,error:0};
      secs = {};
      document.querySelectorAll('#tb tr:not(.sh)').forEach(function(r){
        if (r.dataset.sub !== subF) return;
        var st2=r.dataset.status, lvl=r.dataset.level, sn=r.dataset.secName;
        if (!secs[sn]) secs[sn]={pass:0,fail:0,error:0,score:0};
        if (st2==='PASS')       { counts.PASS++;  secs[sn].pass++;  (lvl==='L1'?l1:l2).pass++; }
        else if (st2==='FAIL')  { counts.FAIL++;  secs[sn].fail++;  (lvl==='L1'?l1:l2).fail++; }
        else if (st2==='ERROR') { counts.ERROR++; secs[sn].error++; (lvl==='L1'?l1:l2).error++; }
      });
      Object.keys(secs).forEach(function(sn){
        var d=secs[sn];
        d.score=Math.round(d.pass/Math.max(d.pass+d.fail+d.error,1)*1000)/10;
      });
    }
    ['d-overall','d-l1','d-l2'].forEach(function(id){
      var cv=document.getElementById(id);
      if(cv) cv.getContext('2d').clearRect(0,0,cv.width,cv.height);
    });
    drawDonut('d-overall',counts.PASS,counts.FAIL,counts.ERROR);
    drawDonut('d-l1',l1.pass,l1.fail,l1.error);
    drawDonut('d-l2',l2.pass,l2.fail,l2.error);
    renderSectionBreakdown(secs);
    function scoreColor(sc){ return sc>=80?'#16a34a':sc>=60?'#d97706':'#dc2626'; }
    function pct(p,f,e){ return Math.round(p/Math.max(p+f+e,1)*1000)/10; }
    var sc=pct(counts.PASS,counts.FAIL,counts.ERROR);
    var l1s=pct(l1.pass,l1.fail,l1.error);
    var l2s=pct(l2.pass,l2.fail,l2.error);
    [['pct-overall',sc],['pct-l1',l1s],['pct-l2',l2s]].forEach(function(pair){
      var el=document.getElementById(pair[0]);
      if(el){ el.textContent=pair[1]+'%'; el.style.color=scoreColor(pair[1]); }
    });
    var ot=counts.PASS+counts.FAIL+counts.ERROR;
    var l1t=l1.pass+l1.fail+l1.error;
    var l2t=l2.pass+l2.fail+l2.error;
    [['cnt-overall',counts.PASS,ot],['cnt-l1',l1.pass,l1t],['cnt-l2',l2.pass,l2t]].forEach(function(t){
      var el=document.getElementById(t[0]);
      if(el) el.textContent=t[1]+' / '+t[2]+' pass';
    });
  }

  updateCharts();

  function drawDonut(id,pass,fail,error){
    var cv=document.getElementById(id);
    if(!cv) return;
    var ctx=cv.getContext('2d');
    var cx=55,cy=55,r=44,ri=28;
    var total=pass+fail+error;
    if(total===0) return;
    var segs=[[pass,'#16a34a'],[fail,'#dc2626'],[error,'#cbd5e1']];
    var start=-Math.PI/2;
    segs.forEach(function(seg){
      if(!seg[0]) return;
      var arc=(seg[0]/total)*2*Math.PI;
      ctx.beginPath();
      ctx.moveTo(cx+r*Math.cos(start),cy+r*Math.sin(start));
      ctx.arc(cx,cy,r,start,start+arc);
      ctx.arc(cx,cy,ri,start+arc,start,true);
      ctx.closePath(); ctx.fillStyle=seg[1]; ctx.fill();
      start+=arc;
    });
    ctx.beginPath(); ctx.arc(cx,cy,ri-1,0,2*Math.PI);
    ctx.fillStyle='#fff'; ctx.fill();
  }

  function renderSectionBreakdown(data){
    data = data || JS_SECTIONS;
    var el=document.getElementById('sec-breakdown');
    if(!el) return;
    var secs=Object.keys(data)
      .filter(function(a){ return data[a].pass+data[a].fail+data[a].error>0; })
      .sort(function(a,b){ return data[a].score-data[b].score; });
    var h='<div class="sb-title">Section Breakdown<span class="sb-subtitle">worst &rarr; best</span></div>';
    secs.forEach(function(sec){
      var d=data[sec];
      var scored=d.pass+d.fail+d.error;
      var col=d.score>=80?'#16a34a':d.score>=60?'#d97706':'#dc2626';
      var pw=scored?Math.round(d.pass/scored*100):0;
      var fw=scored?Math.round(d.fail/scored*100):0;
      var ew=Math.max(0,100-pw-fw);
      h+='<div class="sb-row">'
        +'<div class="sb-name" title="'+sec+'">'+sec+'</div>'
        +'<div class="sb-bar">'
        +'<span style="width:'+pw+'%;background:#16a34a"></span>'
        +'<span style="width:'+fw+'%;background:#dc2626"></span>'
        +'<span style="width:'+ew+'%;background:#cbd5e1"></span>'
        +'</div>'
        +'<span class="sb-pct" style="color:'+col+'">'+d.score+'%</span>'
        +'</div>';
    });
    el.innerHTML=h;
  }

  /* CSV / JSON export */
  function allRows(){
    var rows=[];
    document.querySelectorAll('#tb tr:not(.sh)').forEach(function(r){
      var cells=r.querySelectorAll('td');
      rows.push({
        control: cells[0]?cells[0].textContent.trim():'',
        level:   cells[1]?cells[1].textContent.trim():'',
        title:   cells[2]?cells[2].textContent.trim():'',
        sub_resource: cells[3]?cells[3].textContent.trim().replace(/\s+/g,' '):'',
        status:  r.dataset.status||'',
        details: cells[5]?cells[5].textContent.trim().replace(/\s+/g,' '):''
      });
    });
    return rows;
  }

  window.exportCsv = function(){
    var rows=allRows();
    var hdr='Control,Level,Title,Subscription/Resource,Status,Details\n';
    var body=rows.map(function(r){
      return [r.control,r.level,r.title,r.sub_resource,r.status,r.details]
        .map(function(v){ return '"'+v.replace(/"/g,'""')+'"'; }).join(',');
    }).join('\n');
    var a=document.createElement('a');
    a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(hdr+body);
    a.download='cis_audit_export.csv'; a.click();
  };

  window.exportJson = function(){
    var a=document.createElement('a');
    a.href='data:application/json;charset=utf-8,'+encodeURIComponent(JSON.stringify(allRows(),null,2));
    a.download='cis_audit_export.json'; a.click();
  };

})();
</script>
</body>
</html>
"@

    [System.IO.File]::WriteAllText($OutputPath, $html, [System.Text.Encoding]::UTF8)
}
