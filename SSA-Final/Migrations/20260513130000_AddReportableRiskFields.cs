using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SSA_Final.Data;

#nullable disable

namespace SSA_Final.Migrations
{
    [DbContext(typeof(SSA_FinalContext))]
    [Migration("20260513130000_AddReportableRiskFields")]
    public partial class AddReportableRiskFields : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "BlocklistSource",
                table: "DomainAnalysisResults",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "IsBlocklistMatch",
                table: "DomainAnalysisResults",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<int>(
                name: "OverallRiskScore",
                table: "DomainAnalysisResults",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "TopRiskSignal",
                table: "DomainAnalysisResults",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TopRiskSignalDetail",
                table: "DomainAnalysisResults",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "TopRiskSignalScore",
                table: "DomainAnalysisResults",
                type: "int",
                nullable: false,
                defaultValue: 0);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "BlocklistSource",
                table: "DomainAnalysisResults");

            migrationBuilder.DropColumn(
                name: "IsBlocklistMatch",
                table: "DomainAnalysisResults");

            migrationBuilder.DropColumn(
                name: "OverallRiskScore",
                table: "DomainAnalysisResults");

            migrationBuilder.DropColumn(
                name: "TopRiskSignal",
                table: "DomainAnalysisResults");

            migrationBuilder.DropColumn(
                name: "TopRiskSignalDetail",
                table: "DomainAnalysisResults");

            migrationBuilder.DropColumn(
                name: "TopRiskSignalScore",
                table: "DomainAnalysisResults");
        }
    }
}
