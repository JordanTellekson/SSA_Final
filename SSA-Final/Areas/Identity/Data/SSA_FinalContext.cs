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
            entity.Property(x => x.BaseDomain).IsRequired();

            entity.HasMany(x => x.Variants)
                .WithOne()
                .HasForeignKey(x => x.DomainScanId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<DomainAnalysisResult>(entity =>
        {
            entity.HasKey(x => x.Id);
            entity.Property(x => x.DiscoveredDomain).IsRequired();
            entity.Property(x => x.Summary).IsRequired();
            entity.PrimitiveCollection(x => x.Indicators);
        });
    }
}
