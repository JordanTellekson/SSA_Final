// File: SSA_FinalContext.cs
// Purpose: Defines project behavior and data flow for phishing-domain analysis and reporting.

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SSA_Final.Models;

namespace SSA_Final.Data;

public class SSA_FinalContext : IdentityDbContext<IdentityUser>
{
    public DbSet<DomainScan> DomainScans => Set<DomainScan>();
    public DbSet<DomainAnalysisResult> DomainAnalysisResults => Set<DomainAnalysisResult>();

    public SSA_FinalContext(DbContextOptions<SSA_FinalContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<DomainScan>(entity =>
        {
            entity.HasKey(x => x.Id);

            // Cap at 450 chars (well above the 253-char DNS maximum) so the column
            // can be indexed — nvarchar(max) is not indexable in SQL Server.
            entity.Property(x => x.BaseDomain).IsRequired().HasMaxLength(450);

            entity.HasMany(x => x.Variants)
                .WithOne()
                .HasForeignKey(x => x.DomainScanId)
                .OnDelete(DeleteBehavior.Cascade);

            // Performance indexes for filtered list queries and deduplication checks.
            entity.HasIndex(x => x.BaseDomain).HasDatabaseName("IX_DomainScans_BaseDomain");
            entity.HasIndex(x => x.Status).HasDatabaseName("IX_DomainScans_Status");
            entity.HasIndex(x => x.CreatedAt).HasDatabaseName("IX_DomainScans_CreatedAt");
            entity.HasIndex(x => x.NumMaliciousDomains).HasDatabaseName("IX_DomainScans_NumMaliciousDomains");
        });

        builder.Entity<DomainAnalysisResult>(entity =>
        {
            entity.HasKey(x => x.Id);
            entity.Property(x => x.DiscoveredDomain).IsRequired();

            // Cap at 50 chars (values are Low/Medium/High/Critical) so the column can be indexed.
            entity.Property(x => x.RiskClassification).IsRequired().HasMaxLength(50);

            entity.Property(x => x.Summary).IsRequired();
            entity.PrimitiveCollection(x => x.Indicators);

            // Performance indexes for variant-level filtering and reporting queries.
            entity.HasIndex(x => x.IsSuspicious).HasDatabaseName("IX_DomainAnalysisResults_IsSuspicious");
            entity.HasIndex(x => x.IsBlocklistMatch).HasDatabaseName("IX_DomainAnalysisResults_IsBlocklistMatch");
            entity.HasIndex(x => x.RiskClassification).HasDatabaseName("IX_DomainAnalysisResults_RiskClassification");
        });
    }
}
