using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SSA_Final.Data;

#nullable disable

namespace SSA_Final.Migrations
{
    [DbContext(typeof(SSA_FinalContext))]
    [Migration("20260512190000_AddRiskClassification")]
    public partial class AddRiskClassification : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "RiskClassification",
                table: "DomainAnalysisResults",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "Low");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RiskClassification",
                table: "DomainAnalysisResults");
        }
    }
}
