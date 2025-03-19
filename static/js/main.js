/**
 * WebSp1der - Frontend JavaScript
 * Desenvolvido por: mairinkdev (https://github.com/mairinkdev)
 */

$(document).ready(function() {
    // Variáveis globais
    let scanInterval;
    let currentScanId;

    // Lidar com o envio do formulário
    $('#scanForm').on('submit', function(e) {
        e.preventDefault();
        
        // Obter valores do formulário
        const formData = {
            url: $('#url').val(),
            scan_type: $('#scan_type').val(),
            threads: $('#threads').val(),
            timeout: $('#timeout').val(),
            proxy: $('#proxy').val()
        };
        
        // Validar URL
        if (!formData.url.startsWith('http://') && !formData.url.startsWith('https://')) {
            alert('URL inválida! Use http:// ou https://');
            return;
        }
        
        // Iniciar escaneamento
        startScan(formData);
    });
    
    // Iniciar escaneamento
    function startScan(formData) {
        // Mostrar status do escaneamento
        $('#noScanMessage').addClass('d-none');
        $('#scanStatus').removeClass('d-none');
        $('#resultsCard').addClass('d-none');
        $('#statusMessage').text('Iniciando escaneamento...');
        $('#progressBar').css('width', '0%');
        
        // Desabilitar botão de iniciar
        $('#startScanBtn').prop('disabled', true);
        
        // Enviar solicitação para iniciar o escaneamento
        $.ajax({
            url: '/start_scan',
            type: 'POST',
            data: formData,
            success: function(response) {
                if (response.status === 'success') {
                    // Armazenar ID do escaneamento
                    currentScanId = response.scan_id;
                    
                    // Atualizar mensagem
                    $('#statusMessage').text('Escaneamento em andamento...');
                    
                    // Iniciar verificação periódica do status
                    scanInterval = setInterval(checkScanStatus, 2000);
                } else {
                    // Exibir erro
                    $('#statusMessage').text('Erro: ' + response.message);
                    $('#scanSpinner').hide();
                    $('#startScanBtn').prop('disabled', false);
                }
            },
            error: function(xhr, status, error) {
                // Exibir erro
                $('#statusMessage').text('Erro ao iniciar escaneamento: ' + error);
                $('#scanSpinner').hide();
                $('#startScanBtn').prop('disabled', false);
            }
        });
    }
    
    // Verificar status do escaneamento
    function checkScanStatus() {
        $.ajax({
            url: '/scan_status',
            type: 'GET',
            success: function(response) {
                // Atualizar barra de progresso
                if (response.progress) {
                    $('#progressBar').css('width', response.progress + '%');
                }
                
                // Verificar status
                if (response.status === 'completed') {
                    // Escaneamento concluído
                    clearInterval(scanInterval);
                    $('#statusMessage').text('Escaneamento concluído!');
                    $('#scanSpinner').hide();
                    $('#startScanBtn').prop('disabled', false);
                    
                    // Obter resultados
                    getScanResults();
                } else if (response.status === 'error') {
                    // Erro no escaneamento
                    clearInterval(scanInterval);
                    $('#statusMessage').text('Erro: ' + response.message);
                    $('#scanSpinner').hide();
                    $('#startScanBtn').prop('disabled', false);
                }
            },
            error: function(xhr, status, error) {
                // Erro ao verificar status
                clearInterval(scanInterval);
                $('#statusMessage').text('Erro ao verificar status: ' + error);
                $('#scanSpinner').hide();
                $('#startScanBtn').prop('disabled', false);
            }
        });
    }
    
    // Obter resultados do escaneamento
    function getScanResults() {
        $.ajax({
            url: '/scan_results',
            type: 'GET',
            success: function(response) {
                if (response.status === 'success') {
                    // Exibir resultados
                    displayResults(response.results);
                } else {
                    // Exibir mensagem
                    $('#resultsInfo').text('Nenhum resultado disponível.');
                }
            },
            error: function(xhr, status, error) {
                // Exibir erro
                $('#resultsInfo').text('Erro ao obter resultados: ' + error);
            }
        });
    }
    
    // Exibir resultados
    function displayResults(results) {
        // Mostrar card de resultados
        $('#resultsCard').removeClass('d-none');
        
        // Contadores de vulnerabilidades
        let highCount = 0;
        let mediumCount = 0;
        let lowCount = 0;
        let infoCount = 0;
        
        // Lista de vulnerabilidades
        let vulnerabilitiesHtml = '';
        
        // Mostrar apenas as vulnerabilidades, não todo o objeto de resultados
        if (results.vulnerabilities && results.vulnerabilities.length > 0) {
            for (const vuln of results.vulnerabilities) {
                // Determinar severidade
                let severity = vuln.severity || 'info';
                
                // Contar por severidade
                if (severity === 'high' || severity === 'critical') highCount++;
                else if (severity === 'medium') mediumCount++;
                else if (severity === 'low') lowCount++;
                else infoCount++;
                
                // Criar item HTML para a vulnerabilidade
                vulnerabilitiesHtml += `
                    <div class="vulnerability-item ${severity}">
                        <h5>${vuln.name || 'Vulnerabilidade'}</h5>
                        <p>${vuln.description || 'Sem descrição disponível'}</p>
                        ${vuln.url ? `<p><strong>URL:</strong> ${vuln.url}</p>` : ''}
                        ${vuln.details ? `<p><strong>Detalhes:</strong> ${vuln.details}</p>` : ''}
                        ${vuln.parameter ? `<p><strong>Parâmetro:</strong> ${vuln.parameter}</p>` : ''}
                    </div>
                `;
            }
        }
        
        // Atualizar contadores
        const countersHtml = `
            <div class="col-3">
                <div class="count-box high">
                    <h3>${highCount}</h3>
                    <div>Alta</div>
                </div>
            </div>
            <div class="col-3">
                <div class="count-box medium">
                    <h3>${mediumCount}</h3>
                    <div>Média</div>
                </div>
            </div>
            <div class="col-3">
                <div class="count-box low">
                    <h3>${lowCount}</h3>
                    <div>Baixa</div>
                </div>
            </div>
            <div class="col-3">
                <div class="count-box info">
                    <h3>${infoCount}</h3>
                    <div>Info</div>
                </div>
            </div>
        `;
        
        // Adicionar informação resumida
        const scanInfoHtml = `
            <div class="alert alert-secondary mb-3">
                <p><strong>URL Alvo:</strong> ${results.target_url || 'N/A'}</p>
                <p><strong>Tempo de execução:</strong> ${results.scan_duration || 0} segundos</p>
            </div>
        `;
        
        // Atualizar a DOM
        $('#vulnerabilitiesCount').html(countersHtml);
        
        // Se tem vulnerabilidades, exibir
        if (vulnerabilitiesHtml) {
            $('#resultsInfo').html(scanInfoHtml);
            $('#vulnerabilitiesList').html(vulnerabilitiesHtml);
        } else {
            $('#resultsInfo').html(`${scanInfoHtml}<div class="alert alert-success">Nenhuma vulnerabilidade encontrada!</div>`);
            $('#vulnerabilitiesList').html('');
        }
    }
    
    // Exportar relatório
    $('#downloadReportBtn').on('click', function() {
        $.ajax({
            url: '/export_report',
            type: 'POST',
            data: { format: 'json' },
            success: function(response) {
                if (response.status === 'success') {
                    // Criar link para download
                    const link = document.createElement('a');
                    link.href = `/reports/${response.filename}`;
                    link.download = response.filename;
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                } else {
                    alert('Erro ao exportar relatório: ' + response.message);
                }
            },
            error: function(xhr, status, error) {
                alert('Erro ao exportar relatório: ' + error);
            }
        });
    });
}); 