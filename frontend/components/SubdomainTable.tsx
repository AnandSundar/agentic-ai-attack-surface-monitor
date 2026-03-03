'use client';

import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  flexRender,
  createColumnHelper,
  type SortingState,
} from '@tanstack/react-table';
import { useState } from 'react';
import type { Finding } from '@/lib/types';
import { RiskBadge } from './RiskBadge';

interface SubdomainTableProps {
  findings: Finding[];
  isLoading?: boolean;
}

const columnHelper = createColumnHelper<Finding>();

const columns = [
  columnHelper.accessor('subdomain', {
    header: 'Subdomain',
    cell: (info) => (
      <span className="font-mono text-sm text-freeze">{info.getValue()}</span>
    ),
  }),
  columnHelper.accessor('risk', {
    header: 'Risk',
    cell: (info) => <RiskBadge risk={info.getValue()} />,
  }),
  columnHelper.accessor('tech', {
    header: 'Tech Stack',
    cell: (info) => {
      const tech = info.getValue();
      const version = info.row.original.tech_version;
      return (
        <span className="text-sm text-purple-medium">
          {tech || 'Unknown'}
          {version && <span className="text-purple-heavy"> ({version})</span>}
        </span>
      );
    },
  }),
  columnHelper.accessor('open_ports', {
    header: 'Open Ports',
    cell: (info) => {
      const ports = info.getValue();
      // Handle case where ports might be undefined, null, or not an array
      if (!ports || !Array.isArray(ports) || ports.length === 0) {
        return <span className="text-purple-heavy">-</span>;
      }
      return (
        <span className="text-sm text-ice">
          {Array.isArray(ports) ? ports.join(', ') : String(ports)}
        </span>
      );
    },
  }),
  columnHelper.accessor('outdated', {
    header: 'Outdated',
    cell: (info) => {
      const outdated = info.getValue();
      if (outdated) {
        return (
          <span className="px-2 py-1 bg-[#ff4d4d]/20 text-[#ff4d4d] text-xs rounded">
            Yes
          </span>
        );
      }
      return <span className="text-purple-heavy">No</span>;
    },
  }),
];

export function SubdomainTable({ findings, isLoading }: SubdomainTableProps) {
  const [sorting, setSorting] = useState<SortingState>([]);

  const table = useReactTable({
    data: findings,
    columns,
    state: {
      sorting,
    },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  if (isLoading && findings.length === 0) {
    return (
      <div className="bg-freeze/5 border border-purple-medium/30 rounded-xl p-6">
        <h3 className="text-lg font-semibold text-freeze mb-4">Subdomain Details</h3>
        <div className="text-center py-8 text-purple-heavy animate-pulse">
          Loading findings...
        </div>
      </div>
    );
  }

  if (findings.length === 0) {
    return (
      <div className="bg-freeze/5 border border-purple-medium/30 rounded-xl p-6">
        <h3 className="text-lg font-semibold text-freeze mb-4">Subdomain Details</h3>
        <div className="text-center py-8 text-purple-heavy">
          No findings yet
        </div>
      </div>
    );
  }

  return (
    <div className="bg-freeze/5 border border-purple-medium/30 rounded-xl p-6">
      <h3 className="text-lg font-semibold text-freeze mb-4">
        Subdomain Details ({findings.length})
      </h3>
      
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id} className="border-b border-purple-medium/30">
                {headerGroup.headers.map((header) => (
                  <th
                    key={header.id}
                    className="px-4 py-3 text-left text-sm font-medium text-purple-heavy cursor-pointer hover:text-ice transition-colors"
                    onClick={header.column.getToggleSortingHandler()}
                  >
                    <div className="flex items-center gap-2">
                      {flexRender(
                        header.column.columnDef.header,
                        header.getContext()
                      )}
                      {header.column.getIsSorted() && (
                        <span className="text-ice">
                          {header.column.getIsSorted() === 'asc' ? '↑' : '↓'}
                        </span>
                      )}
                    </div>
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map((row) => (
              <tr
                key={row.id}
                className="border-b border-purple-medium/20 hover:bg-freeze/5 transition-colors"
              >
                {row.getVisibleCells().map((cell) => (
                  <td key={cell.id} className="px-4 py-3">
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
