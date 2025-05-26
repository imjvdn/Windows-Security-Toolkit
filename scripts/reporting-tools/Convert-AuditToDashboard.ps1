<#
.SYNOPSIS
    Converts security audit data to an interactive HTML dashboard.
.DESCRIPTION
    This script takes security audit data from CSV files and generates an
    interactive HTML dashboard with charts and visualizations to make the
    data easier to understand and analyze.
.PARAMETER InputPath
    Path to the directory containing security audit CSV files.
.PARAMETER OutputPath
    Path where the HTML dashboard will be saved.
.PARAMETER DashboardTitle
    Title for the dashboard.
.EXAMPLE
    .\Convert-AuditToDashboard.ps1 -InputPath "C:\AuditData" -OutputPath "C:\Reports" -DashboardTitle "Security Audit Dashboard"
    
    Converts audit data in C:\AuditData to an HTML dashboard saved in C:\Reports.
.NOTES
    File Name      : Convert-AuditToDashboard.ps1
    Author         : Windows Security Toolkit Team
    Prerequisite   : PowerShell 5.1 or later
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$InputPath,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\SecurityDashboard_$(Get-Date -Format 'yyyyMMdd_HHmmss')"),
    
    [Parameter(Mandatory = $false)]
    [string]$DashboardTitle = "Windows Security Audit Dashboard"
)

# Ensure output directory exists
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Function to convert CSV to JSON
function ConvertTo-JSON {
    param (
        [Parameter(Mandatory = $true)]
        [string]$CsvPath
    )
    
    if (Test-Path -Path $CsvPath) {
        $csvData = Import-Csv -Path $CsvPath
        return $csvData | ConvertTo-Json -Depth 10
    } else {
        Write-Warning "CSV file not found: $CsvPath"
        return "[]"
    }
}

# Function to create a basic chart configuration
function New-ChartConfig {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ChartId,
        
        [Parameter(Mandatory = $true)]
        [string]$ChartTitle,
        
        [Parameter(Mandatory = $true)]
        [string]$ChartType,
        
        [Parameter(Mandatory = $true)]
        [string]$DataVariable,
        
        [Parameter(Mandatory = $false)]
        [string]$CategoryField = "",
        
        [Parameter(Mandatory = $false)]
        [string]$ValueField = "",
        
        [Parameter(Mandatory = $false)]
        [string[]]$Colors = @("#4e73df", "#1cc88a", "#36b9cc", "#f6c23e", "#e74a3b")
    )
    
    $config = @"
    {
        "chartId": "$ChartId",
        "chartTitle": "$ChartTitle",
        "chartType": "$ChartType",
        "dataVariable": "$DataVariable",
        "categoryField": "$CategoryField",
        "valueField": "$ValueField",
        "colors": $(ConvertTo-Json -InputObject $Colors)
    }
"@
    
    return $config
}

# Main execution
try {
    Write-Host "Starting conversion of audit data to HTML dashboard..." -ForegroundColor Cyan
    
    # Check for required CSV files
    $userAccountsCsv = Get-ChildItem -Path $InputPath -Filter "*UserAccounts*.csv" -Recurse | Select-Object -First 1
    $systemInfoCsv = Get-ChildItem -Path $InputPath -Filter "*SystemInfo*.csv" -Recurse | Select-Object -First 1
    $networkSecurityCsv = Get-ChildItem -Path $InputPath -Filter "*NetworkSecurity*.csv" -Recurse | Select-Object -First 1
    $complianceCsv = Get-ChildItem -Path $InputPath -Filter "*Compliance*.csv" -Recurse | Select-Object -First 1
    
    # Convert CSV data to JSON
    $userAccountsJson = if ($userAccountsCsv) { ConvertTo-JSON -CsvPath $userAccountsCsv.FullName } else { "[]" }
    $systemInfoJson = if ($systemInfoCsv) { ConvertTo-JSON -CsvPath $systemInfoCsv.FullName } else { "[]" }
    $networkSecurityJson = if ($networkSecurityCsv) { ConvertTo-JSON -CsvPath $networkSecurityCsv.FullName } else { "[]" }
    $complianceJson = if ($complianceCsv) { ConvertTo-JSON -CsvPath $complianceCsv.FullName } else { "[]" }
    
    # Create chart configurations
    $charts = @()
    
    if ($userAccountsCsv) {
        $charts += New-ChartConfig -ChartId "userAccountsChart" -ChartTitle "User Account Status" -ChartType "pie" -DataVariable "userAccountsData" -CategoryField "AccountStatus" -ValueField "Count"
    }
    
    if ($networkSecurityCsv) {
        $charts += New-ChartConfig -ChartId "firewallStatusChart" -ChartTitle "Firewall Status" -ChartType "doughnut" -DataVariable "networkSecurityData" -CategoryField "Status" -ValueField "Count"
    }
    
    if ($complianceCsv) {
        $charts += New-ChartConfig -ChartId "complianceChart" -ChartTitle "Compliance Status" -ChartType "bar" -DataVariable "complianceData" -CategoryField "Category" -ValueField "CompliancePercentage"
    }
    
    $chartsJson = $charts | ConvertTo-Json -Depth 10
    
    # Create HTML dashboard
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$DashboardTitle</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css">
    <style>
        :root {
            --primary-color: #4e73df;
            --success-color: #1cc88a;
            --info-color: #36b9cc;
            --warning-color: #f6c23e;
            --danger-color: #e74a3b;
            --secondary-color: #858796;
            --light-color: #f8f9fc;
            --dark-color: #5a5c69;
        }
        
        body {
            background-color: var(--light-color);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .navbar {
            background-color: white;
            box-shadow: 0 0.15rem 1.75rem 0 rgba(58, 59, 69, 0.15);
        }
        
        .sidebar {
            min-height: 100vh;
            background-color: var(--primary-color);
            background-image: linear-gradient(180deg, var(--primary-color) 10%, #224abe 100%);
            box-shadow: 0 0.15rem 1.75rem 0 rgba(58, 59, 69, 0.15);
        }
        
        .sidebar-link {
            color: rgba(255, 255, 255, 0.8);
            padding: 1rem;
            display: block;
            text-decoration: none;
            transition: all 0.2s;
        }
        
        .sidebar-link:hover {
            color: white;
            background-color: rgba(255, 255, 255, 0.1);
        }
        
        .sidebar-link.active {
            color: white;
            font-weight: bold;
        }
        
        .card {
            box-shadow: 0 0.15rem 1.75rem 0 rgba(58, 59, 69, 0.15);
            margin-bottom: 1.5rem;
        }
        
        .card-header {
            background-color: white;
            border-bottom: 1px solid #e3e6f0;
            font-weight: bold;
            color: var(--dark-color);
        }
        
        .chart-container {
            height: 20rem;
        }
        
        .stat-card {
            border-left: 0.25rem solid;
            border-radius: 0.35rem;
        }
        
        .stat-card.primary {
            border-left-color: var(--primary-color);
        }
        
        .stat-card.success {
            border-left-color: var(--success-color);
        }
        
        .stat-card.info {
            border-left-color: var(--info-color);
        }
        
        .stat-card.warning {
            border-left-color: var(--warning-color);
        }
        
        .stat-card.danger {
            border-left-color: var(--danger-color);
        }
        
        .stat-card .stat-icon {
            font-size: 2rem;
            opacity: 0.3;
        }
        
        .stat-card .stat-value {
            font-size: 1.5rem;
            font-weight: bold;
        }
        
        .stat-card .stat-label {
            font-size: 0.875rem;
            color: var(--secondary-color);
            text-transform: uppercase;
        }
        
        .table-container {
            max-height: 400px;
            overflow-y: auto;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-lg-2 p-0 sidebar">
                <div class="text-center py-4">
                    <h4 class="text-white">Windows Security Toolkit</h4>
                </div>
                <div class="nav flex-column">
                    <a href="#dashboard" class="sidebar-link active" data-bs-toggle="tab">
                        <i class="bi bi-speedometer2 me-2"></i> Dashboard
                    </a>
                    <a href="#user-accounts" class="sidebar-link" data-bs-toggle="tab">
                        <i class="bi bi-people me-2"></i> User Accounts
                    </a>
                    <a href="#network-security" class="sidebar-link" data-bs-toggle="tab">
                        <i class="bi bi-hdd-network me-2"></i> Network Security
                    </a>
                    <a href="#compliance" class="sidebar-link" data-bs-toggle="tab">
                        <i class="bi bi-check-circle me-2"></i> Compliance
                    </a>
                    <a href="#system-info" class="sidebar-link" data-bs-toggle="tab">
                        <i class="bi bi-info-circle me-2"></i> System Info
                    </a>
                </div>
            </div>
            
            <!-- Main Content -->
            <div class="col-lg-10 p-0">
                <nav class="navbar navbar-expand navbar-light mb-4">
                    <div class="container-fluid">
                        <h5 class="mb-0">$DashboardTitle</h5>
                        <div class="ms-auto">
                            <span class="me-2">Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm")</span>
                        </div>
                    </div>
                </nav>
                
                <div class="container-fluid">
                    <div class="tab-content">
                        <!-- Dashboard Tab -->
                        <div class="tab-pane fade show active" id="dashboard">
                            <!-- Stats Row -->
                            <div class="row mb-4" id="stats-row">
                                <!-- Stats will be dynamically generated -->
                            </div>
                            
                            <!-- Charts Row -->
                            <div class="row">
                                <!-- Charts will be dynamically generated -->
                            </div>
                        </div>
                        
                        <!-- User Accounts Tab -->
                        <div class="tab-pane fade" id="user-accounts">
                            <div class="card">
                                <div class="card-header d-flex justify-content-between align-items-center">
                                    <h6 class="m-0">User Accounts</h6>
                                    <div>
                                        <input type="text" class="form-control form-control-sm" id="user-accounts-search" placeholder="Search...">
                                    </div>
                                </div>
                                <div class="card-body">
                                    <div class="table-container">
                                        <table class="table table-bordered table-hover" id="user-accounts-table">
                                            <thead>
                                                <tr>
                                                    <!-- Headers will be dynamically generated -->
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <!-- Data will be dynamically generated -->
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Network Security Tab -->
                        <div class="tab-pane fade" id="network-security">
                            <div class="card">
                                <div class="card-header d-flex justify-content-between align-items-center">
                                    <h6 class="m-0">Network Security</h6>
                                    <div>
                                        <input type="text" class="form-control form-control-sm" id="network-security-search" placeholder="Search...">
                                    </div>
                                </div>
                                <div class="card-body">
                                    <div class="table-container">
                                        <table class="table table-bordered table-hover" id="network-security-table">
                                            <thead>
                                                <tr>
                                                    <!-- Headers will be dynamically generated -->
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <!-- Data will be dynamically generated -->
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Compliance Tab -->
                        <div class="tab-pane fade" id="compliance">
                            <div class="card">
                                <div class="card-header d-flex justify-content-between align-items-center">
                                    <h6 class="m-0">Compliance Status</h6>
                                    <div>
                                        <input type="text" class="form-control form-control-sm" id="compliance-search" placeholder="Search...">
                                    </div>
                                </div>
                                <div class="card-body">
                                    <div class="table-container">
                                        <table class="table table-bordered table-hover" id="compliance-table">
                                            <thead>
                                                <tr>
                                                    <!-- Headers will be dynamically generated -->
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <!-- Data will be dynamically generated -->
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- System Info Tab -->
                        <div class="tab-pane fade" id="system-info">
                            <div class="card">
                                <div class="card-header">
                                    <h6 class="m-0">System Information</h6>
                                </div>
                                <div class="card-body">
                                    <div class="table-container">
                                        <table class="table table-bordered" id="system-info-table">
                                            <tbody>
                                                <!-- Data will be dynamically generated -->
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.7.1/dist/chart.min.js"></script>
    <script>
        // Data from PowerShell
        const userAccountsData = $userAccountsJson;
        const systemInfoData = $systemInfoJson;
        const networkSecurityData = $networkSecurityJson;
        const complianceData = $complianceJson;
        const chartConfigs = $chartsJson;
        
        // Initialize charts
        const charts = [];
        
        document.addEventListener('DOMContentLoaded', function() {
            // Generate stats
            generateStats();
            
            // Initialize charts
            initializeCharts();
            
            // Initialize tables
            initializeTable('user-accounts-table', userAccountsData);
            initializeTable('network-security-table', networkSecurityData);
            initializeTable('compliance-table', complianceData);
            initializeSystemInfoTable('system-info-table', systemInfoData);
            
            // Initialize search functionality
            initializeSearch('user-accounts-search', 'user-accounts-table');
            initializeSearch('network-security-search', 'network-security-table');
            initializeSearch('compliance-search', 'compliance-table');
            
            // Tab change event
            const tabLinks = document.querySelectorAll('.sidebar-link');
            tabLinks.forEach(link => {
                link.addEventListener('click', function(e) {
                    tabLinks.forEach(l => l.classList.remove('active'));
                    this.classList.add('active');
                });
            });
        });
        
        function generateStats() {
            const statsRow = document.getElementById('stats-row');
            
            // User Accounts Stat
            if (userAccountsData.length > 0) {
                const enabledUsers = userAccountsData.filter(u => u.Enabled === "True").length;
                const totalUsers = userAccountsData.length;
                
                statsRow.innerHTML += `
                    <div class="col-xl-3 col-md-6">
                        <div class="card stat-card primary">
                            <div class="card-body">
                                <div class="row align-items-center">
                                    <div class="col">
                                        <div class="stat-label">Active Users</div>
                                        <div class="stat-value">\${enabledUsers} / \${totalUsers}</div>
                                    </div>
                                    <div class="col-auto">
                                        <i class="bi bi-people stat-icon text-primary"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            }
            
            // Network Security Stat
            if (networkSecurityData.length > 0) {
                const openPorts = networkSecurityData.filter(n => n.Status === "Open").length;
                
                statsRow.innerHTML += `
                    <div class="col-xl-3 col-md-6">
                        <div class="card stat-card info">
                            <div class="card-body">
                                <div class="row align-items-center">
                                    <div class="col">
                                        <div class="stat-label">Open Ports</div>
                                        <div class="stat-value">\${openPorts}</div>
                                    </div>
                                    <div class="col-auto">
                                        <i class="bi bi-hdd-network stat-icon text-info"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            }
            
            // Compliance Stat
            if (complianceData.length > 0) {
                const compliantItems = complianceData.filter(c => c.Status === "Compliant").length;
                const totalItems = complianceData.length;
                const compliancePercentage = Math.round((compliantItems / totalItems) * 100);
                
                let colorClass = "success";
                if (compliancePercentage < 60) {
                    colorClass = "danger";
                } else if (compliancePercentage < 80) {
                    colorClass = "warning";
                }
                
                statsRow.innerHTML += `
                    <div class="col-xl-3 col-md-6">
                        <div class="card stat-card \${colorClass}">
                            <div class="card-body">
                                <div class="row align-items-center">
                                    <div class="col">
                                        <div class="stat-label">Compliance</div>
                                        <div class="stat-value">\${compliancePercentage}%</div>
                                    </div>
                                    <div class="col-auto">
                                        <i class="bi bi-check-circle stat-icon text-\${colorClass}"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            }
            
            // System Info Stat
            if (systemInfoData.length > 0) {
                const osInfo = systemInfoData.find(s => s.Category === "OperatingSystem");
                const osName = osInfo ? osInfo.Value : "Unknown";
                
                statsRow.innerHTML += `
                    <div class="col-xl-3 col-md-6">
                        <div class="card stat-card secondary">
                            <div class="card-body">
                                <div class="row align-items-center">
                                    <div class="col">
                                        <div class="stat-label">OS Version</div>
                                        <div class="stat-value" style="font-size: 1rem;">\${osName}</div>
                                    </div>
                                    <div class="col-auto">
                                        <i class="bi bi-pc-display stat-icon text-secondary"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            }
        }
        
        function initializeCharts() {
            const dashboardTab = document.getElementById('dashboard');
            const chartsRow = dashboardTab.querySelector('.row:nth-child(2)');
            
            chartConfigs.forEach(config => {
                // Create chart container
                const colDiv = document.createElement('div');
                colDiv.className = 'col-xl-6 col-lg-6';
                
                const cardDiv = document.createElement('div');
                cardDiv.className = 'card';
                
                const cardHeaderDiv = document.createElement('div');
                cardHeaderDiv.className = 'card-header';
                cardHeaderDiv.innerHTML = `<h6 class="m-0">\${config.chartTitle}</h6>`;
                
                const cardBodyDiv = document.createElement('div');
                cardBodyDiv.className = 'card-body';
                
                const chartContainerDiv = document.createElement('div');
                chartContainerDiv.className = 'chart-container';
                
                const canvas = document.createElement('canvas');
                canvas.id = config.chartId;
                
                chartContainerDiv.appendChild(canvas);
                cardBodyDiv.appendChild(chartContainerDiv);
                cardDiv.appendChild(cardHeaderDiv);
                cardDiv.appendChild(cardBodyDiv);
                colDiv.appendChild(cardDiv);
                chartsRow.appendChild(colDiv);
                
                // Create chart
                createChart(config);
            });
        }
        
        function createChart(config) {
            const ctx = document.getElementById(config.chartId).getContext('2d');
            
            // Get data based on config
            let data = [];
            let labels = [];
            let values = [];
            
            if (config.dataVariable === 'userAccountsData') {
                // Process user accounts data for chart
                const accountStatusCounts = {};
                userAccountsData.forEach(user => {
                    const status = user.Enabled === "True" ? "Enabled" : "Disabled";
                    accountStatusCounts[status] = (accountStatusCounts[status] || 0) + 1;
                });
                
                labels = Object.keys(accountStatusCounts);
                values = Object.values(accountStatusCounts);
            } else if (config.dataVariable === 'networkSecurityData') {
                // Process network security data for chart
                const statusCounts = {};
                networkSecurityData.forEach(item => {
                    statusCounts[item.Status] = (statusCounts[item.Status] || 0) + 1;
                });
                
                labels = Object.keys(statusCounts);
                values = Object.values(statusCounts);
            } else if (config.dataVariable === 'complianceData') {
                // Process compliance data for chart
                const categoryCounts = {};
                complianceData.forEach(item => {
                    if (!categoryCounts[item.Category]) {
                        categoryCounts[item.Category] = {
                            compliant: 0,
                            nonCompliant: 0,
                            total: 0
                        };
                    }
                    
                    categoryCounts[item.Category].total += 1;
                    if (item.Status === "Compliant") {
                        categoryCounts[item.Category].compliant += 1;
                    } else {
                        categoryCounts[item.Category].nonCompliant += 1;
                    }
                });
                
                labels = Object.keys(categoryCounts);
                values = labels.map(category => {
                    const percentage = (categoryCounts[category].compliant / categoryCounts[category].total) * 100;
                    return Math.round(percentage);
                });
            }
            
            // Create chart based on type
            let chartOptions = {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            };
            
            let chartData = {};
            
            if (config.chartType === 'pie' || config.chartType === 'doughnut') {
                chartData = {
                    labels: labels,
                    datasets: [{
                        data: values,
                        backgroundColor: config.colors,
                        borderWidth: 1
                    }]
                };
            } else if (config.chartType === 'bar') {
                chartData = {
                    labels: labels,
                    datasets: [{
                        label: 'Compliance Percentage',
                        data: values,
                        backgroundColor: config.colors[0],
                        borderWidth: 1
                    }]
                };
                
                chartOptions.scales = {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        title: {
                            display: true,
                            text: 'Percentage (%)'
                        }
                    }
                };
            }
            
            const chart = new Chart(ctx, {
                type: config.chartType,
                data: chartData,
                options: chartOptions
            });
            
            charts.push(chart);
        }
        
        function initializeTable(tableId, data) {
            if (!data || data.length === 0) return;
            
            const table = document.getElementById(tableId);
            const thead = table.querySelector('thead tr');
            const tbody = table.querySelector('tbody');
            
            // Clear existing content
            thead.innerHTML = '';
            tbody.innerHTML = '';
            
            // Get headers from first data item
            const headers = Object.keys(data[0]);
            headers.forEach(header => {
                const th = document.createElement('th');
                th.textContent = header;
                thead.appendChild(th);
            });
            
            // Add data rows
            data.forEach(item => {
                const tr = document.createElement('tr');
                
                headers.forEach(header => {
                    const td = document.createElement('td');
                    td.textContent = item[header];
                    
                    // Add styling based on values
                    if (header === 'Status' || header === 'Enabled') {
                        if (item[header] === 'Compliant' || item[header] === 'True') {
                            td.classList.add('table-success');
                        } else if (item[header] === 'Non-Compliant' || item[header] === 'False') {
                            td.classList.add('table-danger');
                        }
                    }
                    
                    tr.appendChild(td);
                });
                
                tbody.appendChild(tr);
            });
        }
        
        function initializeSystemInfoTable(tableId, data) {
            if (!data || data.length === 0) return;
            
            const table = document.getElementById(tableId);
            const tbody = table.querySelector('tbody');
            
            // Clear existing content
            tbody.innerHTML = '';
            
            // Add data rows
            data.forEach(item => {
                const tr = document.createElement('tr');
                
                const tdCategory = document.createElement('td');
                tdCategory.style.width = '30%';
                tdCategory.style.fontWeight = 'bold';
                tdCategory.textContent = item.Category;
                
                const tdValue = document.createElement('td');
                tdValue.textContent = item.Value;
                
                tr.appendChild(tdCategory);
                tr.appendChild(tdValue);
                tbody.appendChild(tr);
            });
        }
        
        function initializeSearch(searchId, tableId) {
            const searchInput = document.getElementById(searchId);
            if (!searchInput) return;
            
            searchInput.addEventListener('keyup', function() {
                const searchTerm = this.value.toLowerCase();
                const table = document.getElementById(tableId);
                const rows = table.querySelectorAll('tbody tr');
                
                rows.forEach(row => {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(searchTerm) ? '' : 'none';
                });
            });
        }
    </script>
</body>
</html>
"@
    
    # Save HTML dashboard
    $htmlPath = Join-Path -Path $OutputPath -ChildPath "SecurityDashboard.html"
    $htmlContent | Out-File -FilePath $htmlPath -Encoding utf8
    
    Write-Host "HTML dashboard created successfully at: $htmlPath" -ForegroundColor Green
    
    # Open the dashboard in default browser if on Windows
    if ($PSVersionTable.PSVersion.Major -ge 5 -and $PSVersionTable.Platform -ne 'Unix') {
        Start-Process $htmlPath
    }
    
    return $htmlPath
} catch {
    Write-Error "An error occurred while creating the dashboard: $_"
    throw $_
}
