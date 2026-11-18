using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Diagnostics;

using PontoVoz.Api.Cybersecurity.Taint;

namespace PontoVoz.Api.Cybersecurity.Sinks;

/// <summary>
/// Sink de persistência (SQLite, pelo EF Core). Antes de gravar, confere os textos das entidades
/// incluídas ou alteradas. Se algum contém um valor marcado na entrada da requisição, a gravação
/// inteira é recusada: o PontoVoz não precisa armazenar dados pessoais
/// (minimização, LGPD art. 6º, III).
/// </summary>
public sealed class SinkPersistenciaInterceptor(GuardaSinks guarda) : SaveChangesInterceptor
{
    public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result)
    {
        Verificar(eventData.Context);
        return base.SavingChanges(eventData, result);
    }

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
    {
        Verificar(eventData.Context);
        return base.SavingChangesAsync(eventData, result, cancellationToken);
    }

    // Só os valores marcados (taint) são procurados: o seed e os cadastros legítimos não passam
    // pelas regras de padrão, que poderiam recusar um endereço ou nome por semelhança.
    private void Verificar(DbContext? contexto)
    {
        if (contexto is null || guarda.ContextoAtual is not { Estado: EstadoTaint.Contaminado })
        {
            return;
        }

        foreach (EntityEntry entrada in contexto.ChangeTracker.Entries())
        {
            if (entrada.State is not (EntityState.Added or EntityState.Modified))
            {
                continue;
            }

            foreach (PropertyEntry propriedade in entrada.Properties)
            {
                if (propriedade.CurrentValue is string texto && texto.Length > 0)
                {
                    guarda.ExigirSemDadosProtegidos(TipoSink.Persistencia, texto, $"persistencia:{entrada.Metadata.ClrType.Name}.{propriedade.Metadata.Name}",
                        verificarPadroes: false);
                }
            }
        }
    }
}
